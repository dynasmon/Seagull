from __future__ import annotations

from typing import Callable, Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.observability import incr_counter

from .instrumentation import instrument_pool_gauge, instrument_query_timing
from .replication import ReadRouter, ReplicaHandle

_SESSION_KWARGS = dict(
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


def _make_engine(
    database_url: str,
    pool_size: int,
    max_overflow: int,
    connect_timeout_seconds: int | None = None,
) -> Engine:
    is_sqlite = database_url.startswith("sqlite")

    kwargs = dict(
        future=True,
        pool_pre_ping=True,
    )

    if not is_sqlite:
        kwargs["pool_size"] = max(1, int(pool_size))
        kwargs["max_overflow"] = max(0, int(max_overflow))
        kwargs["executemany_mode"] = settings.SEAGULL_DB_EXECUTEMANY_MODE or "values_plus_batch"
        kwargs["executemany_values_page_size"] = max(100, int(settings.SEAGULL_DB_EXECUTEMANY_VALUES_PAGE_SIZE or 1000))
        if connect_timeout_seconds is not None:
            kwargs["connect_args"] = {"connect_timeout": max(1, int(connect_timeout_seconds))}

    try:
        return create_engine(database_url, **kwargs)
    except TypeError:
        for key in ("pool_size", "max_overflow", "executemany_mode", "executemany_values_page_size", "connect_args"):
            kwargs.pop(key, None)
        return create_engine(database_url, **kwargs)


def replica_urls() -> list[str]:
    explicit = [url for url in (settings.DB_REPLICA_URLS or []) if url]
    if explicit:
        return explicit

    built: list[str] = []
    for host_spec in settings.DB_REPLICA_HOSTS or []:
        host, _, port = host_spec.partition(":")
        if not host:
            continue
        built.append(
            URL.create(
                "postgresql",
                username=settings.DB_USER,
                password=settings.DB_PASSWORD or None,
                host=host,
                port=int(port) if port else settings.DB_PORT,
                database=settings.DB_NAME,
            ).render_as_string(hide_password=False)
        )
    return built


def _replica_name(database_url: str) -> str:
    parsed = make_url(database_url)
    return f"{parsed.host or 'replica'}:{parsed.port or 5432}"


def _read_pool_size() -> int:
    return max(1, int(settings.SEAGULL_DB_READ_POOL_SIZE or 50))


def _read_max_overflow() -> int:
    return max(0, int(settings.SEAGULL_DB_READ_MAX_OVERFLOW or 10))


def _build_replicas() -> tuple[ReplicaHandle, ...]:
    handles: list[ReplicaHandle] = []
    for url in replica_urls():
        replica_engine = _make_engine(
            url,
            _read_pool_size(),
            _read_max_overflow(),
            connect_timeout_seconds=settings.SEAGULL_DB_REPLICA_CONNECT_TIMEOUT_SECONDS,
        )
        handles.append(
            ReplicaHandle(
                name=_replica_name(url),
                engine=replica_engine,
                factory=sessionmaker(bind=replica_engine, **_SESSION_KWARGS),
            )
        )
    return tuple(handles)


engine_write: Engine = _make_engine(
    settings.database_url,
    settings.SEAGULL_DB_POOL_SIZE or 10,
    settings.SEAGULL_DB_MAX_OVERFLOW or 20,
)
engine: Engine = engine_write

read_replicas: tuple[ReplicaHandle, ...] = _build_replicas()

read_router = ReadRouter(
    primary=engine_write,
    replicas=read_replicas,
    lag_threshold_bytes=settings.SEAGULL_DB_REPLICA_LAG_THRESHOLD_BYTES,
    degrade_seconds=settings.SEAGULL_DB_REPLICA_LAG_DEGRADE_SECONDS,
    probe_interval_seconds=settings.SEAGULL_DB_REPLICA_PROBE_INTERVAL_SECONDS,
)

if engine_write.dialect.name == "postgresql":
    instrument_query_timing(engine_write, "write")
    write_capacity = max(1, int(settings.SEAGULL_DB_POOL_SIZE or 10)) + max(0, int(settings.SEAGULL_DB_MAX_OVERFLOW or 20))
    instrument_pool_gauge((engine_write,), "write", write_capacity)
    if read_replicas:
        for handle in read_replicas:
            instrument_query_timing(handle.engine, "read")
        read_capacity = len(read_replicas) * (_read_pool_size() + _read_max_overflow())
        instrument_pool_gauge(tuple(handle.engine for handle in read_replicas), "read", read_capacity)

SessionLocalWrite = sessionmaker(bind=engine_write, **_SESSION_KWARGS)
SessionLocal = SessionLocalWrite


class _ReadSessionFactory:
    def __call__(self) -> Session:
        handle = read_router.acquire()
        if handle is None:
            return SessionLocalWrite()
        return handle.factory()


SessionLocalRead = _ReadSessionFactory()


def get_db() -> Iterator[Session]:
    db = SessionLocalWrite()
    try:
        yield db
    finally:
        db.close()


def get_db_write() -> Iterator[Session]:
    db = SessionLocalWrite()
    try:
        yield db
    finally:
        db.close()


def get_db_read() -> Iterator[Session]:
    db = SessionLocalRead()
    try:
        yield db
    finally:
        db.close()


def read_route_enabled(route_key: str) -> bool:
    return route_key in (settings.SEAGULL_DB_READ_ROUTES or [])


def open_routed_session(route_key: str) -> Session:
    if not read_route_enabled(route_key):
        return SessionLocalWrite()
    session = SessionLocalRead()
    served = "read" if session.get_bind() is not engine_write else "write"
    incr_counter("postgres_read_route_total", route=route_key, engine=served)
    return session


def routed_db(route_key: str) -> Callable[[], Iterator[Session]]:
    def dependency() -> Iterator[Session]:
        db = open_routed_session(route_key)
        try:
            yield db
        finally:
            db.close()

    return dependency


def start_replica_monitor() -> None:
    read_router.start_monitor()


def stop_replica_monitor() -> None:
    read_router.stop_monitor()
