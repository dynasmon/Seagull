# Rate limiting

Five endpoints are rate limited: portal login, one-time token redemption,
realtime token issuance, agent enrollment and installer downloads. They all go
through one function, and until now that function could lock a user out
permanently, could be multiplied by the process count without anyone noticing,
grew without bound, and wrote the username it was protecting into the log.

## One window, one round trip

A limit is a counter under `rl:<scope>:<dimension>:<identity>` that expires
after its window. The counter used to be incremented, then read for its TTL,
then given an expiry by a separate `EXPIRE` call. Three round trips, and the
third one was not guaranteed to happen: if the connection dropped between the
`INCR` and the `EXPIRE`, the key stayed at its current count with no expiry at
all. Nothing ever removed it. The identity behind it — an account name, an
address, an agent — was refused every subsequent attempt, forever, and the only
repair was a manual `DEL` in Redis.

The counter is now incremented and given its expiry inside one Lua script, so
Redis either applies both or neither:

```lua
local hits = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {hits, ttl}
```

The `ttl < 0` branch does double duty. On the first hit of a window there is no
expiry yet and it sets one. On a key that lost its expiry — one left behind by
the old code — it puts one back, so the lockout drains itself the next time the
identity is seen instead of persisting until someone notices.

A decision costs one round trip rather than three.

## What happens when Redis is gone

Redis is the shared window. Every API process counts into the same key, which is
what makes a limit of 25 mean 25. When Redis stops answering, that guarantee is
gone and there is no version of the limiter that keeps it. What the platform can
do is choose which way to be wrong, and say so out loud.

`SEAGULL_RATE_LIMIT_DEGRADED_POLICY` names the choice.

| Policy | Behaviour while Redis is unreachable |
|---|---|
| `local` (default) | each API process enforces the limit against its own in-memory windows |
| `deny` | protected endpoints refuse every request until Redis answers again |

`local` keeps the portal usable and keeps a brute-force attempt bounded, at the
cost of the aggregate budget being enforced once per process. `deny` holds the
budget exactly and takes login down with Redis. Neither is right for every
deployment, which is why the default is the one that stays available and the
other is one setting away.

Under `local`, the multiplication is corrected rather than ignored.
`SEAGULL_RATE_LIMIT_LOCAL_PROCESSES` declares how many API processes are
running, and each process enforces `limit / processes`, never less than one
attempt. Compose defaults it to `SEAGULL_UVICORN_WORKERS`, so the two cannot
drift apart by accident. With three processes and a budget of 12, the three
together still admit 12.

The first failure also opens the shared availability circuit in the cache
client, so the next few seconds of requests take the fallback directly instead
of each paying a connect timeout. That circuit belongs to the Redis client
itself now; the limiter no longer keeps a second client and a second circuit of
its own.

## The fallback store has a ceiling

The in-memory windows used to live in a dictionary that nothing ever removed
from. A long outage under a spray of distinct addresses grew it until the
process did. It is now an LRU with a hard ceiling of
`SEAGULL_RATE_LIMIT_LOCAL_MAX_KEYS` entries (default 10000): expired windows are
swept off the front on every hit, and when the ceiling is reached the
least-recently-touched window is dropped to make room. Under 5000 distinct
identities and a ceiling of 64, exactly 64 are held.

Dropping a window is a real loss of enforcement for that identity, and it is the
bounded, deliberate kind: an attacker can flush an entry only by pushing the
ceiling's worth of distinct identities through a single process, during an
outage, and gains one window's worth of attempts for it.

## What reaches the log

Nothing that identifies anyone. The limiter's keys carry usernames and
addresses, and the old fallback wrote the whole key into a warning — on every
request, for as long as Redis was down.

The warning now fires once per transition into the degraded state, not once per
request, and carries the scope, the dimension and the first 12 hex characters of
a SHA-256 of the identity. That is enough to tell whether the failures cluster on
one identity or spread across many, and not enough to recover the account name.

## What it emits

| Metric | Labels | Meaning |
|---|---|---|
| `rate_limit_decisions_total` | `scope`, `backend`, `outcome` | every decision the limiter makes |

`scope` is `login`, `otp`, `realtime-token`, `agent-enroll` or
`agent-installer`. `backend` is `redis` when the shared window answered, `local`
when the process fell back to its own, `denied` under the deny policy.
`outcome` is `allowed` or `limited`.

Anything other than `backend="redis"` means the shared window is unreachable and
raises `RateLimiterWindowDegraded`. Sustained `scope="login"` refusals raise
`LoginRateLimitSustained`, which is a credential-stuffing signal rather than an
infrastructure one — the per-address budget is 25 attempts per five minutes and
the per-account budget is 12, so someone mistyping a password does not reach it.

## Adding a limit

`rate_limit(scope, dimension, identity, limit=..., window_seconds=...)` builds
the key itself. Call sites pass the three parts rather than a formatted string,
which is what keeps the identity out of the log and the `scope` label bounded.
Pick a scope that names the protected operation and a dimension that names what
the identity is — `ip`, `user`, `agent` — and both become metric labels you can
alert on without inventing a key convention.
