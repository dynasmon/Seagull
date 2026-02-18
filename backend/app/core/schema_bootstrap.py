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

                -- Portal-managed fields
                IF NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agents'
                      AND column_name='display_name'
                ) THEN
                    ALTER TABLE agents ADD COLUMN display_name VARCHAR(128);
                END IF;

                IF NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agents'
                      AND column_name='description'
                ) THEN
                    ALTER TABLE agents ADD COLUMN description VARCHAR(512);
                END IF;

                IF NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='agents'
                      AND column_name='tags'
                ) THEN
                    ALTER TABLE agents ADD COLUMN tags JSONB NOT NULL DEFAULT '[]'::jsonb;
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

                -- Cursor pagination uses ORDER BY (timestamp DESC, id DESC)
                -- A composite index helps Postgres satisfy both the filter and the sort efficiently.
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ts_id ON net_events ("timestamp", id)';

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

                -- Cursor pagination uses ORDER BY (created_at DESC, id DESC)
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_alerts_created_at_id ON alerts (created_at, id)';
            END IF;
        END $$;
        """,
        # Indexes: inventory snapshots (history pagination)
        """
        DO $$
        BEGIN
            IF to_regclass('public.agent_inventory_snapshots') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inv_agent_collected_id ON agent_inventory_snapshots (agent_id, collected_at, id)';
            END IF;
        END $$;
        """,
        # Rule overrides (portal-managed)
        """
        CREATE TABLE IF NOT EXISTS alert_rule_overrides (
            rule_id VARCHAR(64) PRIMARY KEY,
            enabled BOOLEAN,
            severity VARCHAR(16),
	        "window" VARCHAR(16),
            cooldown VARCHAR(16),
            min_events INTEGER,
            condition JSONB NOT NULL DEFAULT '{}'::jsonb,
            schedule JSONB NOT NULL DEFAULT '{}'::jsonb,
            patch JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """,
        """
        DO $$
        BEGIN
            IF to_regclass('public.alert_rule_overrides') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_alert_rule_overrides_updated_at ON alert_rule_overrides (updated_at DESC)';
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


        # Lupe (ipinfo) enrichment cache
        """
        CREATE TABLE IF NOT EXISTS ip_enrichment_cache (
            ip VARCHAR(45) PRIMARY KEY,
            country VARCHAR(8) NULL,
            region VARCHAR(128) NULL,
            city VARCHAR(128) NULL,
            loc VARCHAR(32) NULL,
            org VARCHAR(256) NULL,
            asn VARCHAR(32) NULL,
            asn_org VARCHAR(256) NULL,
            data JSONB NOT NULL DEFAULT '{}'::jsonb,
            fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days')
        );
        """,
        """
        DO $$
        BEGIN
            IF to_regclass('public.ip_enrichment_cache') IS NOT NULL THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_ip_enrichment_cache_expires_at ON ip_enrichment_cache (expires_at)';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_ip_enrichment_cache_country ON ip_enrichment_cache (country)';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_ip_enrichment_cache_asn ON ip_enrichment_cache (asn)';
            END IF;

            IF to_regclass('public.net_events') IS NOT NULL THEN
                -- Expression indexes for enriched SSH data (fast filters by country/ASN/org)
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ssh_geo_country_ts ON net_events ((extra->>''geo_country''), "timestamp") WHERE event_type = ''ssh_auth''';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ssh_geo_org_ts ON net_events ((extra->>''geo_org''), "timestamp") WHERE event_type = ''ssh_auth''';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ssh_asn_ts ON net_events ((extra->>''asn''), "timestamp") WHERE event_type = ''ssh_auth''';
            END IF;
        END $$;
        """,
        """
        INSERT INTO search_index_offsets (name, last_id)
        VALUES ('lupe_enricher_ssh_v1', 0)
        ON CONFLICT (name) DO NOTHING;
        """,
        # Portal auth tables (human operators)
        """
        CREATE TABLE IF NOT EXISTS portal_users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(64) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            role VARCHAR(32) NOT NULL DEFAULT 'admin',
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT now(),
            last_login_at TIMESTAMP NULL,
            failed_login_count INTEGER NOT NULL DEFAULT 0
        );
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_portal_users_username ON portal_users (username);
        """,
        """
        CREATE TABLE IF NOT EXISTS portal_refresh_sessions (
            id VARCHAR(36) PRIMARY KEY,
            family_id VARCHAR(36) NOT NULL,
            user_id INTEGER NOT NULL,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT now(),
            expires_at TIMESTAMP NOT NULL,
            revoked_at TIMESTAMP NULL,
            replaced_by_id VARCHAR(36) NULL,
            last_ip VARCHAR(64) NULL,
            last_user_agent VARCHAR(256) NULL
        );
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_portal_refresh_user_id ON portal_refresh_sessions (user_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_portal_refresh_family_id ON portal_refresh_sessions (family_id);
        """,
        """
        CREATE TABLE IF NOT EXISTS portal_one_time_tokens (
            id VARCHAR(36) PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_by_user_id INTEGER NULL,
            label VARCHAR(128) NULL,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT now(),
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP NULL,
            used_ip VARCHAR(64) NULL,
            used_user_agent VARCHAR(256) NULL,
            revoked_at TIMESTAMP NULL
        );
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_portal_otp_user_id ON portal_one_time_tokens (user_id);
        """,
        # Portal login audit events (human operators)
        """
        CREATE TABLE IF NOT EXISTS portal_login_events (
            id VARCHAR(36) PRIMARY KEY,
            user_id INTEGER NULL,
            username VARCHAR(64) NULL,
            method VARCHAR(16) NOT NULL,
            succeeded BOOLEAN NOT NULL DEFAULT TRUE,
            ip VARCHAR(64) NULL,
            user_agent VARCHAR(256) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT now()
        );
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_portal_login_events_created_at ON portal_login_events (created_at DESC);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_portal_login_events_user_id_created_at ON portal_login_events (user_id, created_at DESC);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_portal_login_events_username_created_at ON portal_login_events (username, created_at DESC);
        """,

        # Attack chain cases/steps (stateful incident narrative)
        """
        CREATE INDEX IF NOT EXISTS idx_attack_chain_cases_agent_status_last_seen
            ON attack_chain_cases (agent_id, status, last_seen_at DESC, id DESC);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_attack_chain_cases_suspect_last_seen
            ON attack_chain_cases (suspect_ip, last_seen_at DESC, id DESC);
        """,
        """
        -- Prevent duplicate open cases per (agent_id, suspect_ip).
        -- COALESCE keeps a single "local-only" chain per agent.
        CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_chain_open_case
            ON attack_chain_cases (agent_id, COALESCE(suspect_ip, ''))
            WHERE status = 'open';
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_attack_chain_steps_case_time
            ON attack_chain_steps (case_id, timestamp ASC, id ASC);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_attack_chain_steps_case_fp_created
            ON attack_chain_steps (case_id, fingerprint, created_at DESC);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_attack_chain_steps_stage_time
            ON attack_chain_steps (stage, timestamp DESC, id DESC);
        """,
        """
        CREATE INDEX IF NOT EXISTS gin_attack_chain_cases_context
            ON attack_chain_cases USING GIN (context);
        """,
        """
        CREATE INDEX IF NOT EXISTS gin_attack_chain_steps_details
            ON attack_chain_steps USING GIN (details);
        """,
    ]

    with engine.begin() as conn:
        for s in stmts:
            conn.execute(text(s))
