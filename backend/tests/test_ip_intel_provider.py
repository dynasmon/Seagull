from __future__ import annotations

from pathlib import Path

from app.workers import lupe_enricher


def test_env_alias_prefers_ip_intel_names(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_IP_INTEL_BATCH_SIZE", "777")
    monkeypatch.setenv("SEAGULL_LUPE_BATCH_SIZE", "123")
    assert lupe_enricher._env_int(200, "SEAGULL_IP_INTEL_BATCH_SIZE", "SEAGULL_LUPE_BATCH_SIZE") == 777


def test_resolve_provider_auto_prefers_maxmind(tmp_path: Path, monkeypatch) -> None:
    city = tmp_path / "GeoLite2-City.mmdb"
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    city.write_bytes(b"test")
    asn.write_bytes(b"test")
    monkeypatch.setenv("SEAGULL_IP_INTEL_PROVIDER", "auto")
    monkeypatch.setenv("SEAGULL_IP_INTEL_MAXMIND_CITY_DB_PATH", str(city))
    monkeypatch.setenv("SEAGULL_IP_INTEL_MAXMIND_ASN_DB_PATH", str(asn))
    monkeypatch.setenv("SEAGULL_IPINFO_TOKEN", "token-abc")
    provider, reason = lupe_enricher._resolve_provider(lupe_enricher._provider_config())
    assert provider == lupe_enricher.GEOIP_PROVIDER_MAXMIND
    assert reason.startswith("auto:")


def test_resolve_provider_auto_falls_back_to_ipinfo(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_IP_INTEL_PROVIDER", "auto")
    monkeypatch.delenv("SEAGULL_IP_INTEL_MAXMIND_CITY_DB_PATH", raising=False)
    monkeypatch.delenv("SEAGULL_IP_INTEL_MAXMIND_ASN_DB_PATH", raising=False)
    monkeypatch.setenv("SEAGULL_IPINFO_TOKEN", "token-abc")
    provider, reason = lupe_enricher._resolve_provider(lupe_enricher._provider_config())
    assert provider == lupe_enricher.GEOIP_PROVIDER_IPINFO
    assert reason.startswith("auto:")


def test_build_ipinfo_record_parses_asn() -> None:
    rec = lupe_enricher._build_ipinfo_record(
        {
            "country": "US",
            "region": "Virginia",
            "city": "Ashburn",
            "loc": "39.03,-77.5",
            "org": "AS13335 Cloudflare, Inc.",
        }
    )
    assert rec["asn"] == "AS13335"
    assert rec["asn_org"] == "Cloudflare, Inc."
    assert rec["provider"] == lupe_enricher.GEOIP_PROVIDER_IPINFO
