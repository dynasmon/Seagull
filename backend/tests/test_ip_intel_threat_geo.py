from __future__ import annotations

from app.workers.intelligence.ip_intel import main


def _patch_pass(monkeypatch, *, candidates, cached_ips, wanted=None, failing_ips=None):
    looked_up: list[str] = []
    upserted: list[str] = []
    discarded: list[str] = []
    failing = set(failing_ips or ())

    monkeypatch.setattr(main, "pull_wanted_ips", lambda limit: list(wanted or []))
    monkeypatch.setattr(main, "discard_wanted_ips", lambda ips: discarded.extend(ips))
    monkeypatch.setattr(main, "_fetch_threat_geo_candidates", lambda window, limit: list(candidates))
    monkeypatch.setattr(main, "_get_cached_ip", lambda ip: {"country": "US"} if ip in cached_ips else None)

    def _fake_lookup(ip, provider_name, cfg, timeout_s):
        if ip in failing:
            raise RuntimeError("lookup failed")
        looked_up.append(ip)
        return {"country": "US", "loc": "1.0,2.0", "provider": provider_name}

    monkeypatch.setattr(main, "_lookup_ip", _fake_lookup)
    monkeypatch.setattr(main, "_upsert_cache", lambda ip, rec, ttl_days: upserted.append(ip))
    return looked_up, upserted, discarded


def test_threat_geo_pass_enriches_public_skips_private_and_cached(monkeypatch):
    candidates = ["8.8.8.8", "1.1.1.1", "192.168.1.5", "9.9.9.9"]
    looked_up, upserted, discarded = _patch_pass(monkeypatch, candidates=candidates, cached_ips={"1.1.1.1"})

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
    assert discarded == []


def test_threat_geo_pass_respects_cap(monkeypatch):
    candidates = ["8.8.8.8", "9.9.9.9", "1.0.0.1"]
    _looked_up, upserted, _discarded = _patch_pass(monkeypatch, candidates=candidates, cached_ips=set())

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
    called = {"fetch": 0, "wanted": 0}

    def _fetch(window, limit):
        called["fetch"] += 1
        return ["8.8.8.8"]

    def _wanted(limit):
        called["wanted"] += 1
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "_fetch_threat_geo_candidates", _fetch)
    monkeypatch.setattr(main, "pull_wanted_ips", _wanted)

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
    assert called["wanted"] == 0


def test_threat_geo_pass_prefers_wanted_set_and_discards_processed(monkeypatch):
    wanted = ["45.83.12.7", "192.168.1.5", "1.1.1.1", "9.9.9.9"]
    looked_up, upserted, discarded = _patch_pass(
        monkeypatch,
        candidates=["8.8.8.8"],
        cached_ips={"1.1.1.1"},
        wanted=wanted,
    )

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
    assert upserted == ["45.83.12.7", "9.9.9.9"]
    assert "8.8.8.8" not in looked_up
    assert discarded == ["45.83.12.7", "192.168.1.5", "1.1.1.1", "9.9.9.9"]


def test_threat_geo_pass_keeps_failed_wanted_ips_for_retry(monkeypatch):
    wanted = ["45.83.12.7", "9.9.9.9"]
    _looked_up, upserted, discarded = _patch_pass(
        monkeypatch,
        candidates=[],
        cached_ips=set(),
        wanted=wanted,
        failing_ips={"45.83.12.7"},
    )

    enriched = main._run_threat_geo_pass(
        "maxmind_local",
        {},
        timeout_s=1.0,
        cache_ttl_days=7,
        window_minutes=60,
        cap=10,
        skip_private=True,
    )

    assert enriched == 1
    assert upserted == ["9.9.9.9"]
    assert discarded == ["9.9.9.9"]
