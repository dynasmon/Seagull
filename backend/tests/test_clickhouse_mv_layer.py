from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.core.config import settings
from app.core.integrations import clickhouse as ch_mod

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "infra" / "clickhouse" / "schema"


class _FakeResult:
    def __init__(self, rows: list[tuple]) -> None:
        self.result_rows = rows
        self.first_row = rows[0] if rows else None


class _FakeCh:
    def __init__(self, rows: list[tuple], *, raise_exc: bool = False) -> None:
        self._rows = rows
        self._raise = raise_exc
        self.queries: list[tuple[str, dict | None]] = []

    def query(self, sql: str, parameters: dict | None = None) -> _FakeResult:
        self.queries.append((sql, parameters))
        if self._raise:
            raise RuntimeError("boom")
        return _FakeResult(self._rows)


def test_use_clickhouse_mvs_flag_defaults_to_false() -> None:
    assert bool(settings.SEAGULL_USE_CLICKHOUSE_MVS) is False


def test_mvs_read_enabled_requires_flag_and_clickhouse(monkeypatch) -> None:
    monkeypatch.setattr(ch_mod.settings, "SEAGULL_CLICKHOUSE_ENABLED", True)
    monkeypatch.setattr(ch_mod.settings, "SEAGULL_USE_CLICKHOUSE_MVS", False)
    assert ch_mod.clickhouse_mvs_read_enabled() is False
    monkeypatch.setattr(ch_mod.settings, "SEAGULL_USE_CLICKHOUSE_MVS", True)
    assert ch_mod.clickhouse_mvs_read_enabled() is True
    monkeypatch.setattr(ch_mod.settings, "SEAGULL_CLICKHOUSE_ENABLED", False)
    assert ch_mod.clickhouse_mvs_read_enabled() is False


def test_mv_table_refs_are_database_qualified() -> None:
    db = str(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull") or "seagull")
    assert ch_mod.clickhouse_ddos_volume_1m_table_ref() == f"{db}.net_events_ddos_volume_1m"
    assert ch_mod.clickhouse_src_ips_1m_table_ref() == f"{db}.net_events_src_ips_1m"
    assert ch_mod.clickhouse_ssh_ip_1h_table_ref() == f"{db}.net_events_ssh_ip_1h"
    assert ch_mod.clickhouse_ssh_user_1h_table_ref() == f"{db}.net_events_ssh_user_1h"


def test_schema_files_follow_conventions() -> None:
    files = sorted(SCHEMA_DIR.glob("*.sql"))
    assert files, f"no schema files in {SCHEMA_DIR}"
    for path in files:
        assert re.match(r"^\d{3}_", path.name), path.name
        sql = path.read_text(encoding="utf-8")
        creates = re.findall(r"CREATE (?:TABLE|MATERIALIZED VIEW)", sql)
        guarded = re.findall(r"CREATE (?:TABLE|MATERIALIZED VIEW) IF NOT EXISTS", sql)
        assert creates and len(creates) == len(guarded), path.name
        assert "TTL bucket_ts + toIntervalDay(" in sql, path.name
        assert re.search(r"ENGINE = (SummingMergeTree|AggregatingMergeTree)", sql), path.name
        assert "non_replicated_deduplication_window" in sql, path.name
        assert re.search(r"CREATE MATERIALIZED VIEW IF NOT EXISTS \w+\nTO \w+", sql), path.name


def test_expected_mv_names_match_schema_files_and_bootstrap() -> None:
    schema_mvs: set[str] = set()
    for path in SCHEMA_DIR.glob("*.sql"):
        schema_mvs.update(re.findall(r"CREATE MATERIALIZED VIEW IF NOT EXISTS (\w+)", path.read_text(encoding="utf-8")))
    bootstrap_mvs = {
        "mv_net_events_1m",
        "mv_net_events_proto_intel_1m",
        "mv_net_events_proto_intel_overview_1m",
    }
    assert set(ch_mod.expected_clickhouse_mv_names()) == schema_mvs | bootstrap_mvs


def test_clickhouse_missing_mvs_diffs_against_system_tables() -> None:
    expected = ch_mod.expected_clickhouse_mv_names()
    fake = _FakeCh([(name,) for name in expected[:-2]])
    missing = ch_mod.clickhouse_missing_mvs(fake)
    assert missing == list(expected[-2:])
    sql, params = fake.queries[0]
    assert "system.tables" in sql and "MaterializedView" in sql
    assert params == {"db": str(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"))}

    fake_full = _FakeCh([(name,) for name in expected])
    assert ch_mod.clickhouse_missing_mvs(fake_full) == []


def test_mv_covers_window_guard() -> None:
    start = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    covered = _FakeCh([(datetime(2026, 6, 1, tzinfo=timezone.utc),)])
    assert ch_mod.clickhouse_mv_covers_window(covered, table_ref="db.t", start_ts=start) is True
    naive = _FakeCh([(datetime(2026, 6, 1),)])
    assert ch_mod.clickhouse_mv_covers_window(naive, table_ref="db.t", start_ts=start) is True
    late = _FakeCh([(datetime(2026, 7, 2, tzinfo=timezone.utc),)])
    assert ch_mod.clickhouse_mv_covers_window(late, table_ref="db.t", start_ts=start) is False
    empty = _FakeCh([(None,)])
    assert ch_mod.clickhouse_mv_covers_window(empty, table_ref="db.t", start_ts=start) is False
    broken = _FakeCh([], raise_exc=True)
    assert ch_mod.clickhouse_mv_covers_window(broken, table_ref="db.t", start_ts=start) is False
    assert "minOrNull(bucket_ts)" in ch_mod.mv_min_bucket_sql("db.t")


def test_ddos_volume_read_sql_reaggregates() -> None:
    sql = ch_mod.ddos_volume_1m_read_sql(with_agent=False)
    assert "sum(packets)" in sql and "max(peak_pps)" in sql and "max(peak_bps)" in sql
    assert "GROUP BY bucket_ts" in sql
    assert "net_events_ddos_volume_1m" in sql
    assert "agent_id =" not in sql
    assert "{start_ts:DateTime('UTC')}" in sql and "{end_ts:DateTime('UTC')}" in sql
    sql_agent = ch_mod.ddos_volume_1m_read_sql(with_agent=True)
    assert "agent_id = {agent_id:String}" in sql_agent


def test_top_ports_and_src_ips_read_sql_reaggregate() -> None:
    ports_sql = ch_mod.top_ports_1m_read_sql(with_agent=True, limit=10)
    assert "sum(total_count)" in ports_sql
    assert "net_events_1m" in ports_sql
    assert "dst_port IS NOT NULL" in ports_sql
    assert ports_sql.rstrip().endswith("LIMIT 10")

    src_sql = ch_mod.top_src_ips_1m_read_sql(with_agent=False, limit=7)
    assert "sum(cnt)" in src_sql
    assert "net_events_src_ips_1m" in src_sql
    assert "src_ip != ''" in src_sql
    assert src_sql.rstrip().endswith("LIMIT 7")


def test_ssh_read_sql_builders() -> None:
    totals = ch_mod.ssh_action_totals_1h_read_sql(with_agent=False, actions=("accepted", "failed_password"))
    assert "sum(cnt)" in totals and "GROUP BY action" in totals
    assert "action IN ('accepted', 'failed_password')" in totals
    assert "{end_ts:" not in totals

    uniq = ch_mod.ssh_unique_ips_1h_read_sql(with_agent=True, actions=("accepted",))
    assert "countIf(has_geo)" in uniq and "max(geo_country)" in uniq and "src_ip != ''" in uniq

    top = ch_mod.ssh_top_ips_1h_read_sql(with_agent=False, actions=("accepted",), limit=5)
    assert "max(geo_country) AS geo_country" in top and top.rstrip().endswith("LIMIT 5")

    users = ch_mod.ssh_top_users_1h_read_sql(with_agent=False, actions=("failed_password", "invalid_user"), limit=3)
    assert "net_events_ssh_user_1h" in users and "username != ''" in users

    ips = ch_mod.ssh_source_ips_1h_read_sql(with_agent=True, actions=("accepted",), limit=100)
    assert "GROUP BY src_ip" in ips and ips.rstrip().endswith("LIMIT 100")


def test_ssh_action_literals_are_validated() -> None:
    with pytest.raises(ValueError):
        ch_mod.ssh_action_totals_1h_read_sql(with_agent=False, actions=("accepted", "bad'; DROP TABLE x"))
