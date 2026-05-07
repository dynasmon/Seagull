from __future__ import annotations

import json
from urllib.parse import quote
from urllib.request import Request, urlopen

from .normalization import GEOIP_PROVIDER_IPINFO, _parse_asn


def _fetch_ipinfo(ip: str, token: str, timeout_s: float) -> dict:
    url = f"https://ipinfo.io/{quote(ip, safe='')}/json"
    if token:
        url = f"{url}?token={quote(token, safe='')}"
    req = Request(url, headers={"User-Agent": "seagull-lupe/1.0"})
    with urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def _build_ipinfo_record(ipinfo: dict) -> dict:
    country = ipinfo.get("country")
    region = ipinfo.get("region")
    city = ipinfo.get("city")
    loc = ipinfo.get("loc")
    org = ipinfo.get("org")
    asn, asn_org = _parse_asn(org)

    return {
        "country": country,
        "region": region,
        "city": city,
        "loc": loc,
        "org": org,
        "asn": asn,
        "asn_org": asn_org,
        "provider": GEOIP_PROVIDER_IPINFO,
        "data": {
            "provider": GEOIP_PROVIDER_IPINFO,
            "raw": ipinfo,
        },
    }
