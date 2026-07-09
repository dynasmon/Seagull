from __future__ import annotations

from app.shared.es_hosts import es_hosts


def test_single_host() -> None:
    assert es_hosts("http://es01:9200") == ["http://es01:9200"]


def test_multiple_hosts_with_whitespace() -> None:
    assert es_hosts("http://es01:9200, http://es02:9200 ,http://es03:9200") == [
        "http://es01:9200",
        "http://es02:9200",
        "http://es03:9200",
    ]


def test_empty_falls_back_to_default() -> None:
    assert es_hosts(None) == ["http://elasticsearch:9200"]
    assert es_hosts("  ") == ["http://elasticsearch:9200"]
    assert es_hosts("", default="http://es01:9200") == ["http://es01:9200"]


def test_trailing_commas_ignored() -> None:
    assert es_hosts("http://es01:9200,,") == ["http://es01:9200"]
