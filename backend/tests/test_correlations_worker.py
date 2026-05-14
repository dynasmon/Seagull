from __future__ import annotations


def test_correlations_worker_runtime_imports() -> None:
    from app.features.correlations.worker_runtime import (  # noqa: F401
        CorrelationsWorkerConfig,
        load_enabled_rules,
        load_worker_config,
        run_correlation_cycle,
    )


def test_correlations_worker_package_imports() -> None:
    from app.workers.intelligence.correlations import main  # noqa: F401
    from app.workers.intelligence.correlations.runner import run_once  # noqa: F401
    from app.workers.intelligence.correlations.state import CorrelationsWorkerState  # noqa: F401


def test_correlations_worker_config_defaults(monkeypatch) -> None:
    for name in (
        "SEAGULL_CORRELATIONS_INTERVAL_SECONDS",
        "SEAGULL_CORRELATIONS_MAX_ALERTS",
        "SEAGULL_CORRELATIONS_MAX_AGE_MINUTES",
        "SEAGULL_CORRELATIONS_LOG_EVERY_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)

    from app.features.correlations import worker_runtime
    cfg = worker_runtime.load_worker_config()
    assert cfg.interval_seconds == 60.0
    assert cfg.max_alerts == 5000
    assert cfg.max_age_minutes == 60
    assert cfg.log_every_seconds == 60.0


def test_correlations_worker_config_env(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_CORRELATIONS_INTERVAL_SECONDS", "120")
    monkeypatch.setenv("SEAGULL_CORRELATIONS_MAX_ALERTS", "1000")
    monkeypatch.setenv("SEAGULL_CORRELATIONS_MAX_AGE_MINUTES", "30")
    monkeypatch.setenv("SEAGULL_CORRELATIONS_LOG_EVERY_SECONDS", "10")

    from app.features.correlations import worker_runtime
    cfg = worker_runtime.load_worker_config()
    assert cfg.interval_seconds == 120.0
    assert cfg.max_alerts == 1000
    assert cfg.max_age_minutes == 30
    assert cfg.log_every_seconds == 10.0


def test_correlations_worker_disabled_via_manager(monkeypatch) -> None:
    from app.workers.manager import ChildSpec

    spec = ChildSpec(
        name="correlations",
        module="app.workers.intelligence.correlations.main",
        enabled_env="SEAGULL_CORRELATIONS_WORKER_ENABLED",
        enabled_default=True,
    )
    monkeypatch.delenv("SEAGULL_CORRELATIONS_WORKER_ENABLED", raising=False)
    assert spec.is_enabled() is True

    monkeypatch.setenv("SEAGULL_CORRELATIONS_WORKER_ENABLED", "false")
    assert spec.is_enabled() is False

    monkeypatch.setenv("SEAGULL_CORRELATIONS_WORKER_ENABLED", "1")
    assert spec.is_enabled() is True


def test_correlations_worker_cycle_calls_service(monkeypatch) -> None:
    import app.workers.intelligence.correlations.runner as runner_mod
    from app.features.correlations.worker_runtime import CorrelationsWorkerConfig
    from app.workers.intelligence.correlations.state import CorrelationsWorkerState

    call_log: dict = {"cycles": 0, "rule_calls": 0}

    class _FakeResult:
        rules_evaluated = 2
        alerts_scanned = 50
        incidents = [object()]

    def _fake_load_enabled_rules():
        call_log["rule_calls"] += 1
        return [object()]

    def _fake_run_correlation_cycle(cfg):
        call_log["cycles"] += 1
        return _FakeResult()

    monkeypatch.setattr(runner_mod, "load_enabled_rules", _fake_load_enabled_rules)
    monkeypatch.setattr(runner_mod, "run_correlation_cycle", _fake_run_correlation_cycle)

    cfg = CorrelationsWorkerConfig(
        interval_seconds=60.0,
        max_alerts=500,
        max_age_minutes=60,
        log_every_seconds=0.0,
    )
    state = CorrelationsWorkerState()
    result = runner_mod.run_once(cfg, state)

    assert result is True
    assert call_log["cycles"] == 1
    assert call_log["rule_calls"] == 1
    assert state.cycle_count == 1


def test_correlations_worker_idle_when_no_rules(monkeypatch) -> None:
    import app.workers.intelligence.correlations.runner as runner_mod
    from app.features.correlations.worker_runtime import CorrelationsWorkerConfig
    from app.workers.intelligence.correlations.state import CorrelationsWorkerState

    monkeypatch.setattr(runner_mod, "load_enabled_rules", lambda: [])

    cfg = CorrelationsWorkerConfig(
        interval_seconds=60.0,
        max_alerts=500,
        max_age_minutes=60,
        log_every_seconds=0.0,
    )
    state = CorrelationsWorkerState()
    result = runner_mod.run_once(cfg, state)

    assert result is False
    assert state.cycle_count == 0


def test_correlations_worker_state_log_throttle() -> None:
    from app.workers.intelligence.correlations.state import CorrelationsWorkerState

    state = CorrelationsWorkerState()
    assert state.should_log_ok(60.0) is True
    state.mark_ok_logged()
    assert state.should_log_ok(60.0) is False
    assert state.should_log_ok(0.0) is True

    assert state.should_log_idle(60.0) is True
    state.mark_idle_logged()
    assert state.should_log_idle(60.0) is False


def test_correlations_manager_child_spec_present() -> None:
    from app.workers.manager import GROUPS

    children = {spec.name: spec for spec in GROUPS["intelligence"]}
    assert "correlations" in children
    spec = children["correlations"]
    assert spec.module == "app.workers.intelligence.correlations.main"
    assert spec.enabled_env == "SEAGULL_CORRELATIONS_WORKER_ENABLED"
    assert spec.enabled_default is True
