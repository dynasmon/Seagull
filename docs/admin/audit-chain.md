# The audit chain

Every admin action and every login writes a row to `admin_audit_events`, and
every row carries `event_hash` and `prev_event_hash`. Those two columns are a
promise: that the trail is append-only and that a later edit is detectable.

The columns existed. The promise did not. There was no verifier anywhere in the
codebase, the chain forked under ordinary concurrency, retention deleted the
oldest links without leaving anything behind, and — the part that made all of
the above moot — the hash could not be recomputed from the stored row even in
principle.

## The hash did not describe the row

The writer signed a payload it built separately from the row it inserted. The
two disagreed in three places. `created_at` came from one `datetime.utcnow()`
call in the payload and a *second* call for the row, so the signed timestamp was
microseconds off from the stored one. `reason` and `error` were signed at full
length and stored truncated to 255 characters. `resource_id` was signed raw and
stored truncated to 128.

Any verifier reading a row back and recomputing its hash would have reported
every single event as tampered. That is why writing one was never as simple as
it looked, and it is the first thing that had to change: the row is built first,
and `chain.event_payload(row)` derives the signed payload *from the stored row*.
Writer and verifier call the same function on the same shape, so agreement is
structural rather than a thing to keep in sync by hand.

## The chain forked, and had already forked

`_latest_event_hash` read the newest row with `ORDER BY created_at DESC, id DESC`
and no lock. Two transactions reading before either committed would both see the
same predecessor and both claim it. The tie-break did not help: `id` is a random
UUID, so two events in the same microsecond ordered arbitrarily.

This was not theoretical. The development database contained this:

| created_at | event_hash | prev_event_hash |
|---|---|---|
| 16:42:22.161786 | `cbafa13e57` | `d8a8e74019` |
| 16:42:27.884149 | `d8a8e74019` | `c9ba14a114` |
| 16:52:44.247265 | `a8382bb784` | `d8a8e74019` |

The first row points at the hash of the row written five seconds *after* it —
two transactions overlapped and the later-timestamped one committed first. Ten
minutes later a third event read the head by `created_at`, got the same
predecessor again, and `d8a8e74019` ended up with two successors.

Replayed deliberately with eight concurrent writers against PostgreSQL, the old
code produced eight events all pointing at the same predecessor. Not a fork —
a star. As with refresh rotation, the limit is not two; it is however many
transactions read before the first one writes.

## What replaced it

A single row, `audit_chain_head`, holds the sequence number and hash of the
newest link. Writing an event takes that row with `SELECT ... FOR UPDATE`,
numbers the event, links it, advances the head, and lets the caller's
transaction commit both together.

That gives four properties at once:

- **No fork.** The row lock is the serialization point. A second writer waits.
- **Commit-ordered numbering.** `seq` is assigned under a lock held until commit,
  so sequence order *is* commit order. A sequence would not do this — it hands
  out numbers before commit, which is the same trap that lets an indexer skip
  events tailing by `id > last_id`.
- **Atomic rollback.** The head lives in the caller's transaction, so a
  transaction that rolls back consumes no link and leaves no gap.
- **A stable walk order** for the verifier that does not depend on timestamps.

The cost is that audit writes serialize against each other. Audit volume here is
admin actions and logins, and the lock is taken immediately before the caller
commits, so the window is short. If it ever stops being short, the alternative
is sealing ranges into signed batches instead of linking every event.

## Verification

`audit-verifier`, a child of the maintenance worker group, walks the chain in
pages of `SEAGULL_AUDIT_VERIFY_BATCH` every
`SEAGULL_AUDIT_VERIFY_EVERY_SECONDS` (default 900). For each event it checks
that the stored `prev_event_hash` matches the previous event's hash, and that
recomputing the hash from the stored row reproduces `event_hash`.

The three ways to tamper leave different signatures, verified against a live
database:

| What was done | What the verifier reports |
|---|---|
| edited a stored field | `event_hash_mismatch` on that event |
| deleted an event | `seq_gap` and `prev_hash_mismatch` on the next one |
| repointed a link, content untouched | `prev_hash_mismatch` and `event_hash_mismatch` |

## Retention leaves an anchor

Retention used to delete the oldest rows in batches. Once the oldest surviving
event's predecessor was gone, nothing could say whether it had been pruned on
schedule or removed by someone.

Pruning now walks in `seq` order and writes an `audit_chain_checkpoints` row
before deleting: the range pruned, how many rows, and the hash of the last one
removed. That last hash is exactly what the first survivor points at, so the
verifier validates straight across the boundary. Checkpoints are themselves
chained to each other, so removing one is as visible as removing an event —
the range it covered reports `missing_predecessor`.

## Events written before the chain

Rows that predate this work were numbered by the migration in `(created_at, id)`
order, but their hashes were produced by the old scheme and cannot verify. The
head row records `chain_from_seq`, the first sequence number that belongs to the
serialized chain, and verification starts there. Older rows keep their columns
and age out through retention. On the development database that floor landed at
1596, leaving 1595 rows below it.

## What it emits

| Metric | Labels | Meaning |
|---|---|---|
| `audit_chain_verification_total` | `outcome` | `intact`, `broken` or `error` per pass |
| `audit_chain_broken_links` | `reason` | links that failed the last pass, by kind |
| `audit_chain_verified_events` | | events walked by the last pass |
| `audit_chain_length` | | sequence number of the newest link |
| `audit_chain_verify_seconds` | | pass duration |
| `audit_chain_checkpoints_total` | | checkpoints written before a prune |

`AuditChainBroken` fires on the first non-zero break because one is already the
signal. `AuditChainVerifierSilent` fires when nothing has reported for half an
hour, which is the state this whole mechanism exists to avoid: evidence that
nobody checks.

## What this still does not give you

The application role that writes the trail can also update and delete it, and the
chain is stored in the same database it protects. Someone with write access to
PostgreSQL can rewrite an event *and* its successors and produce a chain that
verifies — what they cannot do is edit one row and go unnoticed.

Closing that gap means the trail leaving the blast radius: a database role for
the application without `UPDATE`/`DELETE` on `admin_audit_events`, and an export
of sealed checkpoints to append-only storage under a credential the application
does not hold. Both are deployment topology rather than application code, and
belong with the network segmentation and role separation work.
