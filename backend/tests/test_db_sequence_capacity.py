import os

os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import pytest

from app.core.config import settings
from app.core.db import capacity
from app.core.observability.registry import METRIC_SPECS

INT4_MAX = 2147483647


@pytest.fixture(autouse=True)
def clean_cache():
    capacity.reset_sequence_capacity_cache()
    yield
    capacity.reset_sequence_capacity_cache()


def test_report_ranks_the_fullest_sequence_first():
    report = capacity.build_sequence_report(
        [
            {"sequencename": "alerts_id_seq", "last_value": 1000, "max_value": INT4_MAX},
            {"sequencename": "net_events_id_seq", "last_value": INT4_MAX // 2, "max_value": INT4_MAX},
            {"sequencename": "exposure_nodes_id_seq", "last_value": INT4_MAX // 4, "max_value": INT4_MAX},
        ]
    )

    assert [item["sequence"] for item in report] == [
        "net_events_id_seq",
        "exposure_nodes_id_seq",
        "alerts_id_seq",
    ]
    assert report[0]["used_ratio"] == pytest.approx(0.5, abs=1e-6)
    assert report[1]["used_ratio"] == pytest.approx(0.25, abs=1e-6)


def test_report_treats_an_untouched_sequence_as_empty():
    report = capacity.build_sequence_report(
        [{"sequencename": "vuln_findings_id_seq", "last_value": None, "max_value": INT4_MAX}]
    )

    assert report == [
        {
            "sequence": "vuln_findings_id_seq",
            "last_value": 0,
            "max_value": INT4_MAX,
            "used_ratio": 0.0,
        }
    ]


def test_report_marks_a_bigint_sequence_as_effectively_free():
    report = capacity.build_sequence_report(
        [{"sequencename": "net_events_id_seq", "last_value": INT4_MAX, "max_value": 9223372036854775807}]
    )

    assert report[0]["used_ratio"] < 1e-9


def test_report_skips_rows_it_cannot_read():
    report = capacity.build_sequence_report(
        [
            {"sequencename": "", "last_value": 10, "max_value": INT4_MAX},
            {"sequencename": "broken_id_seq", "last_value": "not-a-number", "max_value": INT4_MAX},
            {"sequencename": "zero_id_seq", "last_value": 10, "max_value": 0},
            {"sequencename": "alerts_id_seq", "last_value": 10, "max_value": INT4_MAX},
        ]
    )

    assert [item["sequence"] for item in report] == ["alerts_id_seq"]


def test_ratio_never_exceeds_one_when_a_sequence_is_past_its_maximum():
    report = capacity.build_sequence_report(
        [{"sequencename": "net_events_id_seq", "last_value": INT4_MAX + 500, "max_value": INT4_MAX}]
    )

    assert report[0]["used_ratio"] == 1.0


def test_probe_is_skipped_off_postgres(monkeypatch):
    class Dialect:
        name = "sqlite"

    class Engine:
        dialect = Dialect()

        def connect(self):
            raise AssertionError("the probe must not open a connection off postgres")

    monkeypatch.setattr(capacity, "engine", Engine())

    assert capacity.sequence_capacity_report() == []


def test_probe_publishes_a_gauge_per_sequence(monkeypatch):
    published = []
    monkeypatch.setattr(
        capacity,
        "set_gauge",
        lambda name, value, **labels: published.append((name, value, labels)),
    )
    _install_fake_engine(
        monkeypatch,
        [
            {"sequencename": "net_events_id_seq", "last_value": INT4_MAX // 2, "max_value": INT4_MAX},
            {"sequencename": "alerts_id_seq", "last_value": 0, "max_value": INT4_MAX},
        ],
    )

    capacity.sequence_capacity_report()

    assert published == [
        ("postgres_sequence_used_ratio", pytest.approx(0.5, abs=1e-6), {"sequence": "net_events_id_seq"}),
        ("postgres_sequence_used_ratio", 0.0, {"sequence": "alerts_id_seq"}),
    ]


def test_a_dropped_sequence_is_zeroed_instead_of_left_at_its_last_value(monkeypatch):
    published = []
    monkeypatch.setattr(
        capacity,
        "set_gauge",
        lambda name, value, **labels: published.append((labels["sequence"], value)),
    )
    monkeypatch.setattr(settings, "SEAGULL_DB_SEQUENCE_PROBE_TTL_SECONDS", 0.0)
    rows = [
        {"sequencename": "net_events_id_seq", "last_value": 10, "max_value": INT4_MAX},
        {"sequencename": "scratch_id_seq", "last_value": int(INT4_MAX * 0.9), "max_value": INT4_MAX},
    ]
    _install_fake_engine(monkeypatch, rows)
    capacity.sequence_capacity_report()
    published.clear()

    rows.pop()
    capacity.sequence_capacity_report()

    assert ("scratch_id_seq", 0.0) in published


def test_probe_reuses_the_cached_report_within_the_ttl(monkeypatch):
    monkeypatch.setattr(capacity, "set_gauge", lambda *args, **kwargs: None)
    monkeypatch.setattr(settings, "SEAGULL_DB_SEQUENCE_PROBE_TTL_SECONDS", 300.0)
    calls = _install_fake_engine(
        monkeypatch,
        [{"sequencename": "net_events_id_seq", "last_value": 10, "max_value": INT4_MAX}],
    )

    first = capacity.sequence_capacity_report()
    second = capacity.sequence_capacity_report()

    assert calls["count"] == 1
    assert first == second


def test_probe_keeps_the_last_report_when_the_query_fails(monkeypatch):
    monkeypatch.setattr(capacity, "set_gauge", lambda *args, **kwargs: None)
    monkeypatch.setattr(settings, "SEAGULL_DB_SEQUENCE_PROBE_TTL_SECONDS", 0.0)
    _install_fake_engine(
        monkeypatch,
        [{"sequencename": "net_events_id_seq", "last_value": 10, "max_value": INT4_MAX}],
    )
    healthy = capacity.sequence_capacity_report()

    _install_failing_engine(monkeypatch)

    assert capacity.sequence_capacity_report() == healthy


def test_warn_log_fires_once_per_minute_above_the_floor(monkeypatch):
    logged = []
    monkeypatch.setattr(capacity, "set_gauge", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        capacity,
        "log_event",
        lambda logger, level, event, **fields: logged.append((event, fields)),
    )
    monkeypatch.setattr(settings, "SEAGULL_DB_SEQUENCE_PROBE_TTL_SECONDS", 0.0)
    monkeypatch.setattr(settings, "SEAGULL_DB_SEQUENCE_WARN_RATIO", 0.85)
    _install_fake_engine(
        monkeypatch,
        [{"sequencename": "net_events_id_seq", "last_value": int(INT4_MAX * 0.9), "max_value": INT4_MAX}],
    )

    capacity.sequence_capacity_report()
    capacity.sequence_capacity_report()

    assert len(logged) == 1
    event, fields = logged[0]
    assert event == "sequence_capacity_near_exhaustion"
    assert fields["sequence"] == "net_events_id_seq"
    assert fields["sequences_over_floor"] == 1


def test_warn_log_stays_quiet_below_the_floor(monkeypatch):
    logged = []
    monkeypatch.setattr(capacity, "set_gauge", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        capacity,
        "log_event",
        lambda logger, level, event, **fields: logged.append(event),
    )
    monkeypatch.setattr(settings, "SEAGULL_DB_SEQUENCE_PROBE_TTL_SECONDS", 0.0)
    monkeypatch.setattr(settings, "SEAGULL_DB_SEQUENCE_WARN_RATIO", 0.85)
    _install_fake_engine(
        monkeypatch,
        [{"sequencename": "net_events_id_seq", "last_value": int(INT4_MAX * 0.7), "max_value": INT4_MAX}],
    )

    capacity.sequence_capacity_report()

    assert logged == []


def test_gauge_is_declared_with_a_sequence_label():
    spec = METRIC_SPECS["postgres_sequence_used_ratio"]

    assert spec.kind == "gauge"
    assert spec.labelnames == ("sequence",)
    assert spec.multiproc_mode == "mostrecent"


def _install_fake_engine(monkeypatch, rows):
    calls = {"count": 0}

    class Result:
        def mappings(self):
            return self

        def all(self):
            return list(rows)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, statement):
            calls["count"] += 1
            return Result()

    class Dialect:
        name = "postgresql"

    class Engine:
        dialect = Dialect()

        def connect(self):
            return Connection()

    monkeypatch.setattr(capacity, "engine", Engine())
    return calls


def _install_failing_engine(monkeypatch):
    class Dialect:
        name = "postgresql"

    class Engine:
        dialect = Dialect()

        def connect(self):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(capacity, "engine", Engine())
