from __future__ import annotations

from app.workers.intelligence.ip_intel import main


def _patch_pass(monkeypatch, *, candidates, cached_ips):
    looked_up: list[str] = []
    upserted: list[str] = []

    monkeypatch.setattr(main, "_fetch_threat_geo_candidates", lambda window, limit: list(candidates))
    monkeypatch.setattr(main, "_get_cached_ip", lambda ip: {"country": "US"} if ip in cached_ips else None)

    def _fake_lookup(ip, provider_name, cfg, timeout_s):
        looked_up.append(ip)
        return {"country": "US", "loc": "1.0,2.0", "provider": provider_name}

    monkeypatch.setattr(main, "_lookup_ip", _fake_lookup)
    monkeypatch.setattr(main, "_upsert_cache", lambda ip, rec, ttl_days: upserted.append(ip))
    return looked_up, upserted


def test_threat_geo_pass_enriches_public_skips_private_and_cached(monkeypatch):
    candidates = ["8.8.8.8", "1.1.1.1", "192.168.1.5", "9.9.9.9"]
    looked_up, upserted = _patch_pass(monkeypatch, candidates=candidates, cached_ips={"1.1.1.1"})

    enriched = main._run_threat_geo_pass(
        "maxmind_local",
        {},
        timeout_s=1.0,
        cache_ttl_days=7,
        window_minutes=60,
        cap=10,
        skip_private=True,
    )

    assert enriched == 2
    assert upserted == ["8.8.8.8", "9.9.9.9"]
    assert "192.168.1.5" not in looked_up
    assert "1.1.1.1" not in looked_up


def test_threat_geo_pass_respects_cap(monkeypatch):
    candidates = ["8.8.8.8", "9.9.9.9", "1.0.0.1"]
    _looked_up, upserted = _patch_pass(monkeypatch, candidates=candidates, cached_ips=set())

    enriched = main._run_threat_geo_pass(
        "maxmind_local",
        {},
        timeout_s=1.0,
        cache_ttl_days=7,
        window_minutes=60,
        cap=1,
        skip_private=True,
    )

    assert enriched == 1
    assert upserted == ["8.8.8.8"]


def test_threat_geo_pass_zero_cap_does_no_work(monkeypatch):
    called = {"fetch": 0}

    def _fetch(window, limit):
        called["fetch"] += 1
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "_fetch_threat_geo_candidates", _fetch)

    enriched = main._run_threat_geo_pass(
        "maxmind_local",
        {},
        timeout_s=1.0,
        cache_ttl_days=7,
        window_minutes=60,
        cap=0,
        skip_private=True,
    )

    assert enriched == 0
    assert called["fetch"] == 0
