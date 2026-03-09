from datetime import datetime

from app.core.pagination import decode_cursor, make_cursor_ts_id


def test_cursor_roundtrip_ts_id():
    ts = datetime(2026, 1, 2, 3, 4, 5)
    token = make_cursor_ts_id(ts, 42)
    data = decode_cursor(token)

    assert data["id"] == 42
    assert data["ts"] == ts.isoformat()
