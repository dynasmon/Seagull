# NetWatch Backend Modular Monolith Boundary Note

## Modules identified

Current backend layout is feature-oriented under `app/features/`:

- `account`, `admin`, `agents`, `alerts`, `attack_chain`, `auth`, `correlations`
- `events`, `ingest`, `inventory`, `investigations`, `overview`, `response`
- `settings`, `users`, `vuln`

Cross-cutting/runtime modules are under:

- `app/core` (auth, db, config, audit, lifecycle, observability)
- `app/shared` (taxonomy, protocol intel parsing, indexing contracts)
- `app/workers` (background process entrypoints)

## Main structural problems found

- DB session lifecycle in API handlers was inconsistent:
  - some modules used `Depends(get_db)`
  - some modules opened `SessionLocal()` manually in every endpoint
  - some modules duplicated `_resolve_db` compatibility helpers
- This created repeated route-layer boilerplate and uneven API boundaries.
- Attack-chain worker depended on deep feature internals through many direct imports from `app.features.attack_chain.domain.*` and `models`.

## Changes made (incremental and compatibility-safe)

1. Added a shared API DB boundary helper:
   - `app/core/api_db.py`
   - Provides:
     - `resolve_session(...)`
     - `managed_session(...)` context manager
   - Preserves direct-endpoint-call compatibility used in tests.

2. Normalized API session handling in selected modules:
   - `app/features/account/api.py`
   - `app/features/auth/api.py`
   - `app/features/users/api.py`
   - `app/features/agents/api.py`
   - `app/features/response/api.py`
   - `app/features/attack_chain/api.py`
   - Result:
     - thinner handlers
     - consistent dependency shape (`db: Session = Depends(get_db)`)
     - no repeated ad-hoc session close logic

3. Added explicit worker-facing feature entrypoint for attack chain:
   - `app/features/attack_chain/worker_runtime.py`
   - Re-exports worker-required symbols from attack-chain internals as a stable import surface.

4. Updated attack-chain worker to depend on the new feature entrypoint:
   - `app/workers/attack_chain.py`
   - Keeps behavior unchanged while reducing deep cross-module import coupling.

5. Standardized API DB boundary handling in priority modules:
   - `app/features/events/api.py`
   - `app/features/alerts/api.py`
   - `app/features/inventory/api.py`
   - These now follow the same `managed_session(...)` pattern already used in other APIs.

6. Thinned route orchestration in events API:
   - Added `get_recent_events_view(...)` in `app/features/events/service.py`
   - Moved `/events/recent` search-vs-recent branching out of the route handler.

7. Reduced alerts feature coupling to worker internals:
   - Added `app/features/alerts/rule_runtime.py`
   - `app/features/alerts/service.py` now imports rule runtime symbols from this feature-local adapter instead of importing worker modules directly.

8. Moved proto-intel persistence details into events feature layer:
   - Added `app/features/events/proto_intel_repository.py`
   - `app/workers/proto_intel.py` now delegates offset/batch/update DB operations to this repository.
   - Worker behavior remains unchanged; only layering was improved.

## Intentionally left for later phases

- Full session-handling normalization for every API module (for example, `investigations/api.py` still has high repetition).
- Deeper feature-level contracts to reduce direct model usage from workers beyond the attack-chain path.
- Further decomposition of large service files in priority modules (especially `events/service.py`) into narrower application/domain units.
- Broader consolidation of cross-feature orchestration patterns in service layer.

This phase intentionally prioritized low-risk boundary improvements without changing API, worker runtime behavior, TLS/bootstrap flows, or systemd agent compatibility.
