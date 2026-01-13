"""Database bootstrap helpers.

This project intentionally avoids heavy migration tooling at the foundation stage.
We use idempotent DDL guarded by existence checks.

This bootstrap is safe to run on every backend start.
"""

from sqlalchemy import text


def bootstrap_schema(engine) -> None:
    stmts = [
        # net_events: ensure schema_version column exists
        """
        DO $$
        BEGIN
            IF to_regclass('public.net_events') IS NOT NULL THEN
                IF NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='net_events'
                      AND column_name='schema_version'
                ) THEN
                    ALTER TABLE net_events
                      ADD COLUMN schema_version SMALLINT NOT NULL DEFAULT 1;
                END IF;
            END IF;
        END $$;
        """,
        # Convert JSON -> JSONB for frequently queried fields (enables fast key extraction and expression indexes)
        """
        DO $$
        BEGIN
            IF to_regclass('public.net_events') IS NOT NULL THEN
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='net_events'
                      AND column_name='extra'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE net_events
                      ALTER COLUMN extra TYPE JSONB USING extra::jsonb;
                END IF;
            END IF;

            IF to_regclass('public.alerts') IS NOT NULL THEN
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='alerts'
                      AND column_name='details'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE alerts
                      ALTER COLUMN details TYPE JSONB USING details::jsonb;
                END IF;
            END IF;

            IF to_regclass('public.agents') IS NOT NULL THEN
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agents'
                      AND column_name='metadata'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE agents
                      ALTER COLUMN metadata TYPE JSONB USING metadata::jsonb;
                END IF;
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agents'
                      AND column_name='config'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE agents
                      ALTER COLUMN config TYPE JSONB USING config::jsonb;
                END IF;
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agents'
                      AND column_name='metrics'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE agents
                      ALTER COLUMN metrics TYPE JSONB USING metrics::jsonb;
                END IF;
            END IF;

            IF to_regclass('public.agent_inventory_snapshots') IS NOT NULL THEN
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agent_inventory_snapshots'
                      AND column_name='os'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE agent_inventory_snapshots
                      ALTER COLUMN os TYPE JSONB USING os::jsonb;
                END IF;
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agent_inventory_snapshots'
                      AND column_name='packages'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE agent_inventory_snapshots
                      ALTER COLUMN packages TYPE JSONB USING packages::jsonb;
                END IF;
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agent_inventory_snapshots'
                      AND column_name='extra'
                      AND data_type='json'
                ) THEN
                    ALTER TABLE agent_inventory_snapshots
                      ALTER COLUMN extra TYPE JSONB USING extra::jsonb;
                END IF;
            END IF;
        END $$;
        """,
        # Indexes: net_events (time-bounded queries)
        """
        DO $$
        BEGIN
            IF to_regclass('public.net_events') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ts ON net_events ("timestamp")';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_type_ts ON net_events (event_type, "timestamp")';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_agent_ts ON net_events (agent_id, "timestamp")';

                -- Partial indexes for hot event types (reduce CPU for dashboards under load)
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_flow_ts ON net_events ("timestamp") WHERE event_type = ''flow''';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_dos_ts ON net_events ("timestamp") WHERE event_type = ''dos_attack''';

                -- SSH failures frequently filter by extra.action
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ssh_action_ts ON net_events ((extra->>''action''), "timestamp") WHERE event_type = ''ssh_auth''';
            END IF;
        END $$;
        """,
        # Indexes: agents / alerts
        """
        DO $$
        BEGIN
            IF to_regclass('public.agents') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_agents_last_seen_at ON agents (last_seen_at)';
            END IF;
            IF to_regclass('public.alerts') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at)';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_alerts_sev_created_at ON alerts (severity, created_at)';
            END IF;
        END $$;
        """,
        # Inventory table (safe if DB is fresh and backend hasn't created tables yet)
        """
        CREATE TABLE IF NOT EXISTS agent_inventory_snapshots (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(64) NOT NULL,
            collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            schema_version SMALLINT NOT NULL DEFAULT 1,
            os JSONB NOT NULL DEFAULT '{}'::jsonb,
            packages JSONB NOT NULL DEFAULT '[]'::jsonb,
            packages_hash VARCHAR(64) NOT NULL,
            packages_count INTEGER NOT NULL DEFAULT 0,
            manager VARCHAR(32),
            extra JSONB NOT NULL DEFAULT '{}'::jsonb
        );
        """,
        """
        DO $$
        BEGIN
            IF to_regclass('public.agent_inventory_snapshots') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inv_agent_time ON agent_inventory_snapshots (agent_id, collected_at DESC)';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inv_hash ON agent_inventory_snapshots (agent_id, packages_hash)';
            END IF;
        END $$;
        """,
        # Rollups to reduce dashboard pressure on net_events
        """
        CREATE TABLE IF NOT EXISTS event_rollups_1m (
            bucket_ts TIMESTAMPTZ NOT NULL,
            agent_id VARCHAR(64) NOT NULL,
            event_type VARCHAR(32) NOT NULL,
            count BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_ts, agent_id, event_type)
        );
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_event_rollups_1m_bucket ON event_rollups_1m (bucket_ts DESC);
        """,
        """
        CREATE TABLE IF NOT EXISTS ssh_fail_rollups_1m (
            bucket_ts TIMESTAMPTZ NOT NULL,
            agent_id VARCHAR(64) NOT NULL,
            action VARCHAR(64) NOT NULL,
            count BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_ts, agent_id, action)
        );
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_ssh_fail_rollups_1m_bucket ON ssh_fail_rollups_1m (bucket_ts DESC);
        """,
        # Generic pipeline offsets (Elasticsearch forwarders / rollups / etc.)
        """
        CREATE TABLE IF NOT EXISTS search_index_offsets (
            name TEXT PRIMARY KEY,
            last_id INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """,
        """
        INSERT INTO search_index_offsets (name, last_id)
        VALUES ('events', 0)
        ON CONFLICT (name) DO NOTHING;
        """,
        """
        INSERT INTO search_index_offsets (name, last_id)
        VALUES ('rollup_events_1m', 0)
        ON CONFLICT (name) DO NOTHING;
        """,
        """
        INSERT INTO search_index_offsets (name, last_id)
        VALUES ('rollup_ssh_fail_1m', 0)
        ON CONFLICT (name) DO NOTHING;
        """,
    ]

    with engine.begin() as conn:
        for s in stmts:
            conn.execute(text(s))
