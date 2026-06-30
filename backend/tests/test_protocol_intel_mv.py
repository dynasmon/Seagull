from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from types import SimpleNamespace

from starlette.responses import Response as StarletteResponse

from app.core.cache import locks
from app.features.events import api as events_api
from app.features.events import service
from app.features.events.domain import summaries
from app.features.events.schemas import ProtocolIntelSummaryResponse, QueryProvenanceMeta
from app.shared.analytics import swr


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_response(total: int, *, source: str = "postgres") -> ProtocolIntelSummaryResponse:
    return ProtocolIntelSummaryResponse(
        generated_at=datetime.now(timezone.utc),
        since_minutes=60,
        agent_id=None,
        total_events=total,
        with_proto_metadata=total,
        dns_events=0,
        http_events=0,
        tls_events=0,
        app_protocols=[],
        transport_protocols=[],
        top_dst_ports=[],
        top_src_ports=[],
        app_proto_reasons=[],
        app_proto_conf_bands=[],
        ja4_ptypes=[],
        http_methods=[],
        top_dns_queries=[],
        top_http_hosts=[],
        top_tls_sni=[],
        top_alpn=[],
        top_ja4=[],
        top_ja3=[],
        meta=QueryProvenanceMeta(source=source, fallback_chain=[source]),
    )


def _facet_rows():
    return [
        {"dimension": "app_proto", "value": "quic", "c": 5, "risk": 0, "assoc": ""},
        {"dimension": "transport", "value": "udp", "c": 5, "risk": 0, "assoc": ""},
        {"dimension": "dst_port", "value": "443", "c": 5, "risk": 0, "assoc": ""},
        {"dimension": "src_port", "value": "53000", "c": 5, "risk": 0, "assoc": ""},
        {"dimension": "app_proto_conf_band", "value": "80-100", "c": 5, "risk": 0, "assoc": ""},
        {"dimension": "ja4_ptype", "value": "q", "c": 5, "risk": 0, "assoc": ""},
        {"dimension": "dns_qname", "value": "example.org", "c": 1, "risk": 5, "assoc": ""},
        {"dimension": "tls_sni", "value": "login.example.net", "c": 4, "risk": 0, "assoc": ""},
        {"dimension": "tls_alpn_first", "value": "h2", "c": 4, "risk": 0, "assoc": ""},
        {"dimension": "ja4", "value": "ja4v", "c": 2, "risk": 0, "assoc": "q"},
        {"dimension": "ja3", "value": "ja3v", "c": 3, "risk": 0, "assoc": ""},
    ]


def test_mv_read_single_round_trip_and_parsing(monkeypatch) -> None:
    calls = {"n": 0, "sql": []}

    def fake_ch_query_dicts(_ch, sql, params=None):
        calls["n"] += 1
        calls["sql"].append(sql)
        if "countMerge(total) AS total_events" in sql:
            return [
                {
                    "total_events": 5,
                    "with_proto_metadata": 5,
                    "dns_events": 1,
                    "http_events": 0,
                    "tls_events": 4,
                    "last_ts": _utc_now_iso(),
                }
            ]
        if "GROUP BY dimension, value" in sql:
            return _facet_rows()
        return []

    monkeypatch.setattr(service, "_ch_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_ch_query_dicts", fake_ch_query_dicts)
    monkeypatch.setattr(service, "clickhouse_watermark_lag_seconds", lambda now=None: 1.0)

    out = service.resolve_protocol_intel_summary(db=object(), since_minutes=720, limit=25, agent_id="agent-z")

    assert calls["n"] == 2
    assert out.meta is not None
    assert out.meta.source == "clickhouse"
    assert "clickhouse_mv" in out.meta.fallback_chain
    assert out.total_events == 5
    assert out.app_protocols[0].key == "quic"
    assert out.top_dst_ports[0].key == "443"
    assert out.top_dns_queries[0].qname == "example.org"
    assert out.top_dns_queries[0].risk == 5
    assert out.top_tls_sni[0].key == "login.example.net"
    assert out.top_alpn[0].key == "h2"
    assert out.top_ja4[0].ja4 == "ja4v"
    assert out.top_ja4[0].ptype == "q"
    assert out.app_proto_conf_bands[0].key == "80-100"


def test_mv_read_falls_back_when_watermark_stale(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_ch_query_dicts(_ch, _sql, _params=None):
        calls["n"] += 1
        return []

    monkeypatch.setattr(service, "_ch_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_ch_query_dicts", fake_ch_query_dicts)
    monkeypatch.setattr(service, "clickhouse_watermark_lag_seconds", lambda now=None: 99999.0)
    monkeypatch.setattr(summaries, "get_protocol_intel_summary", lambda *a, **k: _empty_response(3, source="postgres"))

    out = service.resolve_protocol_intel_summary(db=object(), since_minutes=720, limit=25, agent_id=None)

    assert calls["n"] == 0
    assert out.meta is not None
    assert out.meta.source == "postgres"
    assert out.total_events == 3


class _FakeCache:
    def __init__(self):
        self.store: dict[str, dict] = {}

    def get_json(self, key):
        return self.store.get(key)

    def set_json(self, key, payload, ttl_s):
        self.store[key] = payload


def _install_swr(monkeypatch):
    cache = _FakeCache()
    monkeypatch.setattr(swr, "get_json", cache.get_json)
    monkeypatch.setattr(swr, "set_json", cache.set_json)

    async def _acquire(_key, *, ttl_s):
        return "token"

    async def _release(_key, _token):
        return None

    monkeypatch.setattr(locks, "acquire_lock", _acquire)
    monkeypatch.setattr(locks, "release_lock", _release)
    return cache


def test_async_entrypoint_etag_and_cache_hit(monkeypatch) -> None:
    _install_swr(monkeypatch)
    calls = {"n": 0}

    def fake_resolve(*, since_minutes, limit, agent_id):
        calls["n"] += 1
        return _empty_response(11, source="clickhouse")

    monkeypatch.setattr(service, "_resolve_protocol_intel_blocking", fake_resolve)

    async def run():
        p1, e1, o1 = await service.get_protocol_intel_summary_async(since_minutes=60, limit=25, agent_id=None)
        p2, e2, o2 = await service.get_protocol_intel_summary_async(since_minutes=60, limit=25, agent_id=None)
        assert o1 == "miss" and p1["meta"]["cache_hit"] is False
        assert o2 == "fresh" and p2["meta"]["cache_hit"] is True
        assert e1 == e2 and e1.startswith('W/"5-')

    asyncio.run(run())
    assert calls["n"] == 1


def test_async_entrypoint_widens_when_empty(monkeypatch) -> None:
    _install_swr(monkeypatch)

    def fake_resolve(*, since_minutes, limit, agent_id):
        if since_minutes <= 60:
            return _empty_response(0, source="clickhouse")
        return _empty_response(9, source="clickhouse")

    monkeypatch.setattr(service, "_resolve_protocol_intel_blocking", fake_resolve)

    async def run():
        payload, _etag, _outcome = await service.get_protocol_intel_summary_async(
            since_minutes=60, limit=25, agent_id=None, widen_if_empty=True
        )
        assert payload["total_events"] == 9
        assert payload["effective_since_minutes"] == 360

    asyncio.run(run())


def test_service_registers_read_models_and_warm_sets(monkeypatch) -> None:
    from app.shared.analytics import get_read_model, iter_warm_specs

    assert get_read_model("protocol_intel") is not None
    assert get_read_model("ssh_summary") is not None

    monkeypatch.setattr(service, "_prewarm_top_agents", lambda _limit: ["agent-a", "agent-b"])
    specs = iter_warm_specs()
    features = {s.feature for s in specs}
    assert "protocol_intel" in features
    assert "ssh_summary" in features

    pi_global = [s for s in specs if s.feature == "protocol_intel" and s.params.get("agent_id") is None]
    assert {s.params["since_minutes"] for s in pi_global} >= {60, 720, 1440, 10080}
    assert any(s.params.get("agent_id") == "agent-a" for s in specs)


def test_json_endpoint_etag_and_304(monkeypatch) -> None:
    sample = _empty_response(5, source="clickhouse").dict()

    async def fake_async(**_kwargs):
        return sample, 'W/"5-abc"', "miss"

    monkeypatch.setattr(service, "get_protocol_intel_summary_async", fake_async)

    async def run():
        resp = StarletteResponse()
        out = await events_api.get_protocol_intel_summary_endpoint(
            SimpleNamespace(headers={}), resp, since_minutes=60, limit=25, agent_id=None, widen_if_empty=False
        )
        assert isinstance(out, dict)
        assert resp.headers["etag"] == 'W/"5-abc"'

        resp2 = StarletteResponse()
        out2 = await events_api.get_protocol_intel_summary_endpoint(
            SimpleNamespace(headers={"if-none-match": 'W/"5-abc"'}),
            resp2,
            since_minutes=60,
            limit=25,
            agent_id=None,
            widen_if_empty=False,
        )
        assert getattr(out2, "status_code", None) == 304

    asyncio.run(run())


def test_sse_stream_emits_overview_then_facets(monkeypatch) -> None:
    sample = _empty_response(5, source="clickhouse").dict()
    sample["app_protocols"] = [{"key": "tls", "count": 5}]

    async def fake_async(**_kwargs):
        return sample, 'W/"5-abc"', "miss"

    monkeypatch.setattr(service, "get_protocol_intel_summary_async", fake_async)

    async def run():
        resp = await events_api.get_protocol_intel_summary_stream_endpoint(
            since_minutes=60, limit=25, agent_id=None, widen_if_empty=False
        )
        assert resp.headers["etag"] == 'W/"5-abc"'
        frames = []
        async for chunk in resp.body_iterator:
            frames.append(chunk if isinstance(chunk, str) else chunk.decode("utf-8"))
        text = "".join(frames)
        assert text.startswith("event: overview")
        assert text.count("event: facet") == len(events_api._PROTOCOL_INTEL_FACET_KEYS)
        assert "event: done" in text
        assert '"total_events":5' in text

    asyncio.run(run())
