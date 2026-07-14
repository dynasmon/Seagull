import os

os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.db import (
    SessionLocalRead,
    engine_write,
    get_db_read,
    open_routed_session,
    read_route_enabled,
    read_router,
    routed_db,
)
from app.core.db.engine import replica_urls
from app.core.db.instrumentation import statement_table
from app.core.db.replication import ReadRouter, ReplicaHandle, parse_wal_lsn


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _handle(name: str) -> ReplicaHandle:
    engine = create_engine("sqlite://", future=True)
    return ReplicaHandle(name=name, engine=engine, factory=sessionmaker(bind=engine, future=True))


def _router(names: list[str], threshold: int = 1000, degrade_seconds: float = 30.0) -> tuple[ReadRouter, FakeClock]:
    clock = FakeClock()
    router = ReadRouter(
        primary=create_engine("sqlite://", future=True),
        replicas=[_handle(name) for name in names],
        lag_threshold_bytes=threshold,
        degrade_seconds=degrade_seconds,
        probe_interval_seconds=5.0,
        clock=clock,
    )
    return router, clock


def test_parse_wal_lsn() -> None:
    assert parse_wal_lsn("0/0") == 0
    assert parse_wal_lsn("0/16") == 0x16
    assert parse_wal_lsn("16/B374D848") == (0x16 << 32) | 0xB374D848


def test_acquire_without_replicas_returns_none() -> None:
    router, _ = _router([])
    assert router.acquire() is None
    assert router.enabled is False


def test_acquire_requires_fresh_probe() -> None:
    router, clock = _router(["r1"])
    assert router.acquire() is None
    router.record_probe("r1", lag_bytes=0, error=None)
    assert router.acquire() is not None
    clock.advance(16.0)
    assert router.acquire() is None


def test_acquire_round_robins_between_healthy_replicas() -> None:
    router, _ = _router(["r1", "r2"])
    router.record_probe("r1", lag_bytes=0, error=None)
    router.record_probe("r2", lag_bytes=0, error=None)
    picked = [router.acquire().name for _ in range(4)]
    assert set(picked) == {"r1", "r2"}
    assert picked[0] != picked[1]


def test_probe_error_degrades_immediately() -> None:
    router, _ = _router(["r1", "r2"])
    router.record_probe("r1", lag_bytes=0, error=None)
    router.record_probe("r2", lag_bytes=None, error="connection refused")
    picked = {router.acquire().name for _ in range(4)}
    assert picked == {"r1"}


def test_lag_degrades_only_after_sustained_window() -> None:
    router, clock = _router(["r1"], threshold=1000, degrade_seconds=30.0)
    router.record_probe("r1", lag_bytes=0, error=None)
    assert router.acquire() is not None

    router.record_probe("r1", lag_bytes=5000, error=None)
    assert router.acquire() is not None

    clock.advance(10.0)
    router.record_probe("r1", lag_bytes=5000, error=None)
    assert router.acquire() is not None

    clock.advance(25.0)
    router.record_probe("r1", lag_bytes=5000, error=None)
    assert router.acquire() is None

    router.record_probe("r1", lag_bytes=10, error=None)
    assert router.acquire() is not None


def test_all_degraded_falls_back_to_none() -> None:
    router, _ = _router(["r1", "r2"])
    router.record_probe("r1", lag_bytes=None, error="down")
    router.record_probe("r2", lag_bytes=None, error="down")
    assert router.acquire() is None


def test_status_report_shape() -> None:
    router, _ = _router(["r1", "r2"])
    router.record_probe("r1", lag_bytes=123, error=None)
    router.record_probe("r2", lag_bytes=None, error="down")
    report = router.status_report()
    assert report["enabled"] is True
    assert report["total"] == 2
    assert report["healthy"] == 1
    by_name = {entry["name"]: entry for entry in report["replicas"]}
    assert by_name["r1"]["lag_bytes"] == 123
    assert by_name["r1"]["degraded"] is False
    assert by_name["r2"]["degraded"] is True
    assert by_name["r2"]["error"] == "down"


def test_replica_urls_built_from_hosts_quotes_credentials(monkeypatch) -> None:
    monkeypatch.setattr(settings, "DB_REPLICA_URLS", [])
    monkeypatch.setattr(settings, "DB_REPLICA_HOSTS", ["replica-a:6432", "replica-b"])
    monkeypatch.setattr(settings, "DB_USER", "seagull")
    monkeypatch.setattr(settings, "DB_PASSWORD", "p@ss/w:rd")
    monkeypatch.setattr(settings, "DB_PORT", 5432)
    monkeypatch.setattr(settings, "DB_NAME", "seagull")

    urls = replica_urls()
    assert len(urls) == 2

    first = make_url(urls[0])
    assert first.host == "replica-a"
    assert first.port == 6432
    assert first.username == "seagull"
    assert first.password == "p@ss/w:rd"
    assert first.database == "seagull"

    second = make_url(urls[1])
    assert second.host == "replica-b"
    assert second.port == 5432


def test_replica_urls_prefers_explicit_dsns(monkeypatch) -> None:
    monkeypatch.setattr(settings, "DB_REPLICA_URLS", ["postgresql://u:p@h1:5433/db"])
    monkeypatch.setattr(settings, "DB_REPLICA_HOSTS", ["ignored:5444"])
    assert replica_urls() == ["postgresql://u:p@h1:5433/db"]


def test_read_session_falls_back_to_write_engine_without_replicas() -> None:
    assert read_router.enabled is False
    session = SessionLocalRead()
    try:
        assert session.get_bind() is engine_write
    finally:
        session.close()


def test_get_db_read_yields_write_bound_session_without_replicas() -> None:
    gen = get_db_read()
    session = next(gen)
    try:
        assert session.get_bind() is engine_write
    finally:
        gen.close()


def test_read_route_enabled_follows_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_DB_READ_ROUTES", ["agents-list", "vuln-read"])
    assert read_route_enabled("agents-list") is True
    assert read_route_enabled("vuln-read") is True
    assert read_route_enabled("admin-audit-events") is False


def test_open_routed_session_disabled_uses_write(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_DB_READ_ROUTES", [])
    session = open_routed_session("agents-list")
    try:
        assert session.get_bind() is engine_write
    finally:
        session.close()


def test_open_routed_session_enabled_falls_back_without_replicas(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_DB_READ_ROUTES", ["agents-list"])
    session = open_routed_session("agents-list")
    try:
        assert session.get_bind() is engine_write
    finally:
        session.close()


def test_routed_db_dependency_yields_session(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_DB_READ_ROUTES", ["inventory-read"])
    gen = routed_db("inventory-read")()
    session = next(gen)
    try:
        assert session.get_bind() is engine_write
    finally:
        gen.close()


def test_statement_table_extraction() -> None:
    assert statement_table("SELECT id FROM alerts WHERE id = 1") == "alerts"
    assert statement_table('INSERT INTO "net_events" (id) VALUES (1)') == "net_events"
    assert statement_table("UPDATE agents SET last_seen_at = now()") == "agents"
    assert statement_table("SELECT 1") == "none"
    assert statement_table("select a.id from alerts a join agents g on g.id = a.agent_id") == "alerts"
