import threading


class _FakeConn:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _base_patches(monkeypatch, runner, events, conn):
    monkeypatch.setattr(runner.settings, "validate_for_service", lambda *a, **k: None)
    monkeypatch.setattr(runner, "init_counter", lambda *a, **k: None)
    monkeypatch.setattr(runner, "_install_signal_handlers", lambda: None)
    monkeypatch.setattr(runner, "_get_interval_seconds", lambda: 0.0)
    monkeypatch.setattr(runner, "_open_lock_connection", lambda: conn)
    monkeypatch.setattr(runner, "log_event", lambda logger, level, event, **fields: events.append(event))
    ev = threading.Event()
    monkeypatch.setattr(runner, "_stop_event", ev)
    return ev


def test_runner_runs_rules_when_leader_and_releases_on_stop(monkeypatch):
    from app.workers.intelligence.rules import runner

    events = []
    conn = _FakeConn()
    ev = _base_patches(monkeypatch, runner, events, conn)

    run_calls = []

    def fake_run_all_rules():
        run_calls.append(1)
        ev.set()
        return []

    releases = []
    monkeypatch.setattr(runner, "try_acquire_leader_lock", lambda c: True)
    monkeypatch.setattr(runner, "run_all_rules", fake_run_all_rules)
    monkeypatch.setattr(runner, "release_leader_lock", lambda c: releases.append(c))

    runner.main()

    assert len(run_calls) == 1
    assert releases == [conn]
    assert conn.closed is True
    assert "rules_leader_acquired" in events
    assert "rules_cycle_ok" in events
    assert "rules_worker_stopped" in events
    assert events.index("rules_leader_acquired") < events.index("rules_cycle_ok")


def test_runner_stands_by_and_skips_rules_when_not_leader(monkeypatch):
    from app.workers.intelligence.rules import runner

    events = []
    conn = _FakeConn()
    ev = _base_patches(monkeypatch, runner, events, conn)

    run_calls = []

    def fake_run_all_rules():
        run_calls.append(1)
        return []

    def fake_acquire(c):
        ev.set()
        return False

    releases = []
    monkeypatch.setattr(runner, "try_acquire_leader_lock", fake_acquire)
    monkeypatch.setattr(runner, "run_all_rules", fake_run_all_rules)
    monkeypatch.setattr(runner, "release_leader_lock", lambda c: releases.append(c))

    runner.main()

    assert run_calls == []
    assert releases == []
    assert conn.closed is True
    assert "rules_standby_not_leader" in events
    assert "rules_leader_acquired" not in events
    assert "rules_cycle_ok" not in events
    assert "rules_worker_stopped" in events


def test_runner_keeps_leadership_across_cycles_without_reacquiring(monkeypatch):
    from app.workers.intelligence.rules import runner

    events = []
    conn = _FakeConn()
    ev = _base_patches(monkeypatch, runner, events, conn)

    acquire_calls = []

    def fake_acquire(c):
        acquire_calls.append(1)
        return True

    run_calls = []

    def fake_run_all_rules():
        run_calls.append(1)
        if len(run_calls) >= 2:
            ev.set()
        return []

    releases = []
    monkeypatch.setattr(runner, "try_acquire_leader_lock", fake_acquire)
    monkeypatch.setattr(runner, "run_all_rules", fake_run_all_rules)
    monkeypatch.setattr(runner, "release_leader_lock", lambda c: releases.append(c))

    runner.main()

    assert len(acquire_calls) == 1
    assert len(run_calls) == 2
    assert releases == [conn]
