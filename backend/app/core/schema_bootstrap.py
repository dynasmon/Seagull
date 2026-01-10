"""Database bootstrap helpers.

This project intentionally avoids heavy migration tooling at the foundation stage.
We use idempotent DDL guarded by existence checks.
"""

from sqlalchemy import text


def bootstrap_schema(engine) -> None:
    stmts = [
        # net_events: schema_version column
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

        # Indexes: net_events
        """
        DO $$
        BEGIN
            IF to_regclass('public.net_events') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ts ON net_events ("timestamp")';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_type_ts ON net_events (event_type, "timestamp")';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_agent_ts ON net_events (agent_id, "timestamp")';
            END IF;
        END $$;
        """,

        # Indexes: agents
        """
        DO $$
        BEGIN
            IF to_regclass('public.agents') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_agents_last_seen_at ON agents (last_seen_at)';
            END IF;
        END $$;
        """,

        # Indexes: alerts
        """
        DO $$
        BEGIN
            IF to_regclass('public.alerts') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at)';
            END IF;
        END $$;
        """,

        # Inventory table + indexes (created by SQLAlchemy too, but keep safe for manual DBs)
        """
        CREATE TABLE IF NOT EXISTS agent_inventory_snapshots (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(64) NOT NULL,
            collected_at TIMESTAMPTZ NOT NULL,
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
    ]

    with engine.begin() as conn:
        for s in stmts:
            conn.execute(text(s))
