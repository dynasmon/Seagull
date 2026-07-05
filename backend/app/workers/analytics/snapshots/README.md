# Dashboard snapshots worker

Materializa em Postgres o payload agregado das páginas de dashboard mais quentes
(padrão CQRS: compute em background, leitura O(1) no handler). O handler HTTP nunca
chama este worker — toda comunicação acontece via a tabela `dashboard_snapshots`.

## Topologia

```
worker (este processo)                 API (uvicorn)
  tick fixo (30s)                        GET /overview, /vuln/..., ...
  para cada página habilitada              SWR (Redis) --------- fresh? serve
    para cada scope registrado              | miss/revalidate
      lock Redis por scope                  v
      raw_compute(params)              SnapshotPage.compute
      UPSERT dashboard_snapshots  -->    SELECT por (page, scope_key)
                                          fresco? serve : fallback raw_compute
```

Páginas convertidas (uma feature flag por página, rollback = desligar a flag):

| página | flag | scopes |
| --- | --- | --- |
| `overview` | `SEAGULL_SNAPSHOT_OVERVIEW_ENABLED` | estáticos (janelas `SEAGULL_SNAPSHOT_OVERVIEW_WINDOWS` global + lite) + dinâmicos |
| `exposure_summary` | `SEAGULL_SNAPSHOT_EXPOSURE_SUMMARY_ENABLED` | único (global) |
| `network_topology_summary` | `SEAGULL_SNAPSHOT_TOPOLOGY_SUMMARY_ENABLED` | único (global) |
| `vuln_summary` | `SEAGULL_SNAPSHOT_VULN_SUMMARY_ENABLED` | defaults do router |
| `vuln_posture` | `SEAGULL_SNAPSHOT_VULN_POSTURE_ENABLED` | defaults do router |

## Store: por que Postgres (e não ClickHouse)

- Cardinalidade baixa: scopes = páginas globais + agentes efetivamente consultados
  (cap `SEAGULL_SNAPSHOTS_DYNAMIC_MAX_SCOPES`, default 20). O ponto forte do CH
  (bulk write barato, TTL nativo) não pesa com ~1 linha/s.
- Atomicidade real: `INSERT ... ON CONFLICT DO UPDATE` troca a linha inteira numa
  transação — nunca há estado parcial visível. No CH (ReplacingMergeTree) a
  convergência depende de merges e exigiria `FINAL`/`argMax` no read path.
- Disponibilidade: o read path do dashboard não pode depender do CH, que é opcional
  (`SEAGULL_CLICKHOUSE_REQUIRED=false` nos workers) e entra em modo degradado sob
  storm de ingest — exatamente o cenário em que o dashboard mais precisa responder.
- Tabela genérica única (`page` + `scope_key` como PK, payload JSONB) em vez de uma
  tabela por página: todos os leitores fazem o mesmo point-read por PK, não há
  necessidade de indexação fina por página, e novas páginas não exigem migration.
  O versionamento do payload é por página via `schema_version`.

## Registry de scopes

- **Estático (código)**: cada página registra `static_scopes()` junto ao
  `register_snapshot_page(...)` no service da feature (garante que worker e handler
  derivam o mesmo `scope_key` do mesmo `key_builder` do read model).
- **Dinâmico (consulta real)**: páginas com `track_params` (hoje só `overview`)
  gravam cada scope consultado num ZSET Redis (`seagull:snapshots:seen:<page>`,
  score = último acesso). O worker recomputa apenas os scopes vistos nas últimas
  `SEAGULL_SNAPSHOTS_DYNAMIC_WINDOW_HOURS` horas (cap de
  `SEAGULL_SNAPSHOTS_DYNAMIC_MAX_SCOPES`). Assim, overview por agente só é
  materializado para agentes que alguém de fato consultou; o primeiro acesso cai no
  fallback inline e a partir do tick seguinte é servido do snapshot.
- Scopes altamente combinatórios (ranges fixos `start_ts`/`end_ts`, janelas fora do
  preset, params fora do default) são `bypass`: nem consultam o store, seguem SWR
  direto com compute inline.

## Freshness contract

Cada linha carrega `computed_at` e `computed_ms`; o handler expõe ambos em
`meta.snapshot` (com `age_s` e `degraded`) para debug. Regras no handler:

- `age <= 2 × tick` → serve normal (`snapshot_lookup_total{outcome="hit"}`).
- `2 × tick < age <= SEAGULL_SNAPSHOTS_MAX_AGE_MULTIPLIER × tick` → serve com
  `meta.snapshot.degraded=true` (`outcome="degraded"`).
- `age` acima do teto, linha ausente, `schema_version` divergente ou erro de leitura
  → fallback para o compute inline antigo, com warning estruturado
  (`snapshot_fallback_inline_compute`) e `snapshot_fallback_total{reason}`.

O contrato de resposta dos endpoints não muda: o SWR/ETag da Onda 1 continua acima
desta camada, e `meta` é excluído do hash de ETag.

## Concorrência

Múltiplas instâncias do worker podem coexistir: cada scope é protegido por lock
distribuído (`acquire_lock`/`release_lock` de `app/core/cache/locks.py`, a mesma
primitiva do `single_flight` usado no path SWR). Quem não pega o lock pula o scope
(`outcome="locked"`). Sem Redis, assume-se instância única e computa mesmo assim.

## Invalidação

v1 é somente tick fixo (`SEAGULL_SNAPSHOTS_EVERY_SECONDS`, default 30s) — barato,
previsível e suficiente dado que o SWR acima já absorve rajadas. Invalidação por
evento (ex.: alerta crítico publica wake-up via Redis pub/sub para adiantar o tick)
fica para uma iteração seguinte; o desenho atual comporta isso sem mudança de schema.
Retenção: linhas não reescritas há `SEAGULL_SNAPSHOTS_RETENTION_HOURS` (24h) são
podadas — remove scopes dinâmicos que deixaram de ser consultados.

## Métricas (Prometheus)

- `snapshot_compute_seconds{page,scope}` — latência de compute por página+scope
  (label `scope` é a forma compacta `w60:global:lite`, não o scope_key inteiro,
  para manter a cardinalidade limitada).
- `snapshot_oldest_age_seconds{page}` — idade do snapshot mais velho por página.
- `snapshot_fallback_total{page,reason}` — fallbacks inline (missing/stale/schema/error).
- `snapshot_compute_errors_total{page}` — erros de compute no worker.
- `snapshot_lookup_total{page,outcome}` — hit/degraded/bypass/misses no handler.
- `snapshot_writes_total{page,outcome}` / `snapshot_cycle_seconds` /
  `snapshot_store_read_seconds{page}` — saúde do ciclo e custo do point-read.

## Operação

Roda como child `dashboard-snapshots` do grupo `intelligence`
(`python -m app.workers.manager intelligence`), gate por
`SEAGULL_SNAPSHOTS_WORKER_ENABLED`. Backoff automático quando o ClickHouse está em
estado `degraded` (mesmo sinal usado pelo prewarm). Se o worker estiver parado, os
handlers continuam funcionando pelo fallback inline — o custo volta a ser o da Onda 1.
