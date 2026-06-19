from app.workers.intelligence.rules.leader import (
    RULES_LEADER_ADVISORY_LOCK_ID,
    release_leader_lock,
    try_acquire_leader_lock,
)


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _FakeConnection:
    def __init__(self, value):
        self._value = value
        self.calls = []

    def execute(self, statement, params=None):
        self.calls.append((str(statement), params))
        return _FakeResult(self._value)


def test_try_acquire_leader_lock_true():
    conn = _FakeConnection(True)
    assert try_acquire_leader_lock(conn) is True
    assert "pg_try_advisory_lock" in conn.calls[0][0]
    assert conn.calls[0][1] == {"lock_id": RULES_LEADER_ADVISORY_LOCK_ID}


def test_try_acquire_leader_lock_false():
    conn = _FakeConnection(False)
    assert try_acquire_leader_lock(conn) is False


def test_release_leader_lock():
    conn = _FakeConnection(True)
    assert release_leader_lock(conn) is True
    assert "pg_advisory_unlock" in conn.calls[0][0]
    assert conn.calls[0][1] == {"lock_id": RULES_LEADER_ADVISORY_LOCK_ID}


def test_custom_lock_id_is_passed_through():
    conn = _FakeConnection(True)
    try_acquire_leader_lock(conn, lock_id=42)
    assert conn.calls[0][1] == {"lock_id": 42}
