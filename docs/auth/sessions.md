# Single-use sessions and one-time tokens

A refresh token and an OTP are both credentials that may be spent once. The
portal enforced that with a read, a check and a later write, which is not the
same thing: between the check and the write another request can read the same
row and reach the same conclusion. Under PostgreSQL's default READ COMMITTED
isolation nothing prevents it, and neither credential was single-use in the only
window that matters.

`tests/test_auth_token_concurrency.py` reproduces the old behaviour against a
real PostgreSQL: eight simultaneous refreshes on one token minted eight valid
sessions, and eight simultaneous redemptions of one OTP admitted eight logins.
The race does not reproduce on SQLite, which is why the deterministic tests in
`tests/test_auth_single_use_tokens.py` cover the outcomes and this file covers
the interleaving.

## Spending a credential is one statement

Both flows now spend the credential with a conditional update whose predicate is
the invariant itself, and take the returned row as proof of ownership:

```sql
UPDATE portal_refresh_sessions
   SET revoked_at = :now, replaced_by_id = :successor, ...
 WHERE id = :id AND revoked_at IS NULL
RETURNING id;

UPDATE portal_one_time_tokens
   SET used_at = :now, used_ip = :ip, used_user_agent = :agent
 WHERE id = :id AND used_at IS NULL AND revoked_at IS NULL
RETURNING id;
```

The row lock the update takes is the serialisation point. A second request
blocks on it, re-evaluates the predicate once the winner commits, matches
nothing and gets `False` back. No extra isolation level is involved, and the
lock is held for one statement rather than for the length of the request.

The ordering matters as much as the predicate. Rotation used to create the
successor first and revoke the current session afterwards, so a loser had
already inserted a valid session by the time it found out it had lost. The
successor's identifier is now generated before the claim and passed into it, so
the row that names the successor and the row that grants it are decided by the
same statement: **only the winner creates a session, and only the winner sets a
cookie.**

`revoke_refresh_family` carries the same `revoked_at IS NULL` predicate, so
revoking a family no longer rewrites the timestamp of sessions that were revoked
earlier, and running it twice is not different from running it once.

## What the loser gets

A refresh that loses the claim is refused with `401` and changes nothing else.
It mints no session, sets no cookie and does not revoke the family. The client
behind it is signed out and recovers by reloading, because the winner's cookie
is already in the shared jar.

Replaying a token that was rotated earlier is a different thing and keeps its
existing answer: the whole family is revoked and the response is `401 Session
revoked`. The distinction is not a time window, it is a happens-during relation
— losing the claim proves the two requests overlapped, because the row was still
unrevoked when the loser read it.

This is a deliberate trade. Treating a lost race as reuse would make the
semantics uniform, but the portal keeps its access token in memory, so every tab
refreshes at boot: restoring three tabs at once would revoke the family and
force a password login. Treating a late replay as a race would be worse — it
would hand a session to whoever presents a spent token first.

| Situation | Family | Response |
|---|---|---|
| Rotation wins the claim | untouched | `200` with a new refresh cookie |
| Rotation loses the claim | untouched | `401 Invalid refresh token` |
| Token rotated in an earlier request | revoked | `401 Session revoked` |
| Token revoked without a successor | untouched | `401 Invalid refresh token` |
| OTP loses the claim | not applicable | `401 Invalid token` |

## What it emits

| Metric | Labels | Meaning |
|---|---|---|
| `auth_refresh_rotation_total` | `outcome` | `rotated`, `lost_race`, `reuse_detected`, `invalid`, `expired`, `unauthorized`, `missing` |
| `auth_one_time_token_login_total` | `outcome` | `consumed`, `lost_race`, `invalid`, `unauthorized` |

`reuse_detected` is a security signal and `RefreshTokenReuseDetected` fires on a
single occurrence: a legitimate client never holds a rotated token again, so one
event already means either a leak or a client replaying a cookie it should have
dropped. `lost_race` is an operational signal — no session is ever duplicated by
it, but a sustained rate means a caller is not serialising its refreshes, and
somebody is being signed out for it. The rules live in
`infra/prometheus/rules/seagull-auth.yml` with promtool cases in
`infra/prometheus/tests/auth-single-use-tokens.yml`.

## Running the concurrency tests

They are skipped unless pointed at a PostgreSQL, because SQLite cannot produce
the interleaving. Each run creates a throwaway schema, builds the four portal
tables in it, and drops it afterwards, so it never touches an existing dataset:

```bash
SEAGULL_TEST_DB_URL=postgresql+psycopg2://seagull:PASSWORD@127.0.0.1:5432/seagull \
  python -m pytest tests/test_auth_token_concurrency.py
```

Both tests align their contenders on a barrier placed after the credential is
read and before it is spent, so every request holds the same unspent row when
the claims begin. Without that barrier the late arrivals take the replay path
instead, and the test measures scheduling rather than the invariant.
