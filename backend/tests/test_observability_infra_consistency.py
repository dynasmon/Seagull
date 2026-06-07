from __future__ import annotations

import os
import re
import shutil
import subprocess

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import pytest
import yaml

from app.core.observability import metrics as metrics_mod
from app.core.observability import queries, registry

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_PROM_YML = os.path.join(_REPO_ROOT, "infra", "prometheus", "prometheus.yml")
_COMPOSE_YML = os.path.join(_REPO_ROOT, "compose.yml")

WORKER_METRICS_PORT = 9100
WORKER_SERVICES = {
    "seagull-ingest-pipeline": "ingest",
    "seagull-intelligence-worker": "intelligence",
    "seagull-maintenance-worker": "maintenance",
}
MULTIPROC_DIR = "/tmp/seagull-metrics"


def _load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _prom_jobs(cfg: dict) -> dict:
    return {job["job_name"]: job for job in cfg["scrape_configs"]}


def test_prometheus_global_and_external_labels() -> None:
    cfg = _load_yaml(_PROM_YML)
    assert cfg["global"]["scrape_interval"]
    assert cfg["global"]["external_labels"]["monitor"] == "seagull"


def test_prometheus_backend_job_targets_backend() -> None:
    job = _prom_jobs(_load_yaml(_PROM_YML))["seagull-backend"]
    assert job["metrics_path"] == "/metrics"
    static = job["static_configs"][0]
    assert static["targets"] == ["seagull-backend:8000"]
    assert static["labels"]["component"] == "backend"


def test_prometheus_worker_targets_are_consistent() -> None:
    job = _prom_jobs(_load_yaml(_PROM_YML))["seagull-workers"]
    assert job["metrics_path"] == "/metrics"
    found: dict[str, str] = {}
    for static in job["static_configs"]:
        host, _, port = static["targets"][0].partition(":")
        assert int(port) == WORKER_METRICS_PORT
        assert static["labels"]["component"] == "worker"
        found[host] = static["labels"]["worker_group"]
    assert found == WORKER_SERVICES


def test_compose_prometheus_is_internal_and_pinned() -> None:
    prom = _load_yaml(_COMPOSE_YML)["services"]["prometheus"]
    assert prom["image"].startswith("prom/prometheus")
    assert "ports" not in prom
    assert any("retention" in str(part) for part in prom["command"])


def test_compose_has_no_grafana() -> None:
    assert "grafana" not in _load_yaml(_COMPOSE_YML)["services"]


def test_compose_scrape_targets_exist_as_services() -> None:
    services = _load_yaml(_COMPOSE_YML)["services"]
    assert "seagull-backend" in services
    for worker in WORKER_SERVICES:
        assert worker in services


def test_compose_metrics_processes_share_multiproc_dir_and_tmpfs() -> None:
    services = _load_yaml(_COMPOSE_YML)["services"]
    for name in ["seagull-backend", *WORKER_SERVICES]:
        svc = services[name]
        assert svc["environment"]["PROMETHEUS_MULTIPROC_DIR"] == MULTIPROC_DIR
        assert any(MULTIPROC_DIR in entry for entry in (svc.get("tmpfs") or []))


def test_compose_worker_metrics_port_matches_scrape_config() -> None:
    services = _load_yaml(_COMPOSE_YML)["services"]
    for name in WORKER_SERVICES:
        raw = str(services[name]["environment"]["SEAGULL_WORKER_METRICS_PORT"])
        assert str(WORKER_METRICS_PORT) in raw
        assert "ports" not in services[name]


def test_compose_backend_points_at_prometheus_service() -> None:
    backend = _load_yaml(_COMPOSE_YML)["services"]["seagull-backend"]
    assert "prometheus:9090" in str(backend["environment"]["SEAGULL_PROMETHEUS_URL"])


_PROMQL_FUNCS = {
    "sum", "rate", "irate", "increase", "histogram_quantile", "max", "min", "avg", "count",
    "by", "without", "on", "ignoring", "group_left", "group_right", "le", "clamp_min",
    "clamp_max", "vector", "quantile", "topk", "bottomk", "abs", "ceil", "floor", "round",
}
_STRLIT = re.compile(r"\"[^\"]*\"|'[^']*'")
_RANGE = re.compile(r"\[[^\]]*\]")
_IDENT = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")


def _metric_candidates(promql: str, allowed_labels: set[str]) -> list[str]:
    stripped = _RANGE.sub(" ", _STRLIT.sub(" ", promql))
    out: list[str] = []
    for token in _IDENT.findall(stripped):
        if token in _PROMQL_FUNCS or token in allowed_labels:
            continue
        out.append(token)
    return out


def test_every_allowlisted_query_references_only_declared_metrics() -> None:
    declared = set(registry.METRIC_SPECS.keys())
    allowed_labels = {label for spec in registry.METRIC_SPECS.values() for label in spec.labelnames}
    for key, spec in queries.CATALOGUE.items():
        promql = spec.builder("5m")
        candidates = _metric_candidates(promql, allowed_labels)
        assert candidates, f"{key}: no metric token found in {promql!r}"
        for token in candidates:
            base = token[:-7] if token.endswith("_bucket") else token
            assert base in declared, f"{key}: references undeclared metric {token!r} in {promql!r}"


def test_metric_names_follow_prometheus_conventions() -> None:
    for name, spec in registry.METRIC_SPECS.items():
        assert _METRIC_NAME.match(name), name
        assert spec.kind in {"counter", "gauge", "histogram"}, name
        if spec.kind == "counter":
            assert name.endswith("_total"), name
        else:
            assert not name.endswith("_total"), name


def test_all_declared_metrics_are_emittable_and_scrapeable() -> None:
    for name, spec in registry.METRIC_SPECS.items():
        labels = {label: "test" for label in spec.labelnames}
        if spec.kind == "counter":
            metrics_mod.incr_counter(name, **labels)
        elif spec.kind == "gauge":
            metrics_mod.set_gauge(name, 1.0, **labels)
        else:
            metrics_mod.observe_hist(name, 0.1, **labels)

    body, content_type = metrics_mod.render_exposition()
    text = body.decode("utf-8")
    assert "text/plain" in content_type

    series: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        series.add(line.split("{", 1)[0].split(" ", 1)[0].strip())

    for name, spec in registry.METRIC_SPECS.items():
        if spec.kind == "histogram":
            assert f"{name}_bucket" in series, name
        else:
            assert name in series, name


def _docker_compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(["docker", "compose", "version"], capture_output=True, timeout=30)
        return proc.returncode == 0
    except Exception:
        return False


def test_docker_compose_config_is_valid() -> None:
    if not _docker_compose_available():
        pytest.skip("docker compose not available")
    proc = subprocess.run(
        ["docker", "compose", "config", "-q"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
