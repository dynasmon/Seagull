from __future__ import annotations

import os
from typing import Any, Optional

from .normalization import GEOIP_PROVIDER_MAXMIND

_GEOIP_CITY_READER = None
_GEOIP_ASN_READER = None
_GEOIP_CITY_PATH: Optional[str] = None
_GEOIP_ASN_PATH: Optional[str] = None


def _close_geoip_reader(reader) -> None:
    if reader is None:
        return
    try:
        reader.close()
    except Exception:
        return


def _ensure_geoip_readers(city_db_path: str, asn_db_path: str) -> None:
    global _GEOIP_CITY_READER, _GEOIP_ASN_READER, _GEOIP_CITY_PATH, _GEOIP_ASN_PATH

    try:
        import geoip2.database  # type: ignore
    except Exception as e:
        raise RuntimeError("geoip2_dependency_missing") from e

    if city_db_path != _GEOIP_CITY_PATH:
        _close_geoip_reader(_GEOIP_CITY_READER)
        _GEOIP_CITY_READER = None
        _GEOIP_CITY_PATH = city_db_path
    if asn_db_path != _GEOIP_ASN_PATH:
        _close_geoip_reader(_GEOIP_ASN_READER)
        _GEOIP_ASN_READER = None
        _GEOIP_ASN_PATH = asn_db_path

    if _GEOIP_CITY_READER is None and os.path.isfile(city_db_path):
        _GEOIP_CITY_READER = geoip2.database.Reader(city_db_path)
    if _GEOIP_ASN_READER is None and os.path.isfile(asn_db_path):
        _GEOIP_ASN_READER = geoip2.database.Reader(asn_db_path)


def _build_maxmind_record(ip: str, city_db_path: str, asn_db_path: str) -> dict:
    _ensure_geoip_readers(city_db_path, asn_db_path)

    country = None
    region = None
    city = None
    loc = None
    org = None
    asn = None
    asn_org = None
    raw: dict[str, Any] = {"provider": GEOIP_PROVIDER_MAXMIND, "ip": ip}

    if _GEOIP_CITY_READER is not None:
        try:
            city_resp = _GEOIP_CITY_READER.city(ip)
        except Exception:
            city_resp = None
        if city_resp is not None:
            country = getattr(getattr(city_resp, "country", None), "iso_code", None) or getattr(
                getattr(city_resp, "registered_country", None),
                "iso_code",
                None,
            )
            subdivisions = getattr(city_resp, "subdivisions", None)
            if subdivisions is not None:
                region = getattr(getattr(subdivisions, "most_specific", None), "name", None)
            city = getattr(getattr(city_resp, "city", None), "name", None)
            location = getattr(city_resp, "location", None)
            latitude = getattr(location, "latitude", None)
            longitude = getattr(location, "longitude", None)
            if latitude is not None and longitude is not None:
                loc = f"{latitude},{longitude}"
            raw["city"] = {
                "country": country,
                "region": region,
                "city": city,
                "loc": loc,
            }

    if _GEOIP_ASN_READER is not None:
        try:
            asn_resp = _GEOIP_ASN_READER.asn(ip)
        except Exception:
            asn_resp = None
        if asn_resp is not None:
            asn_number = getattr(asn_resp, "autonomous_system_number", None)
            asn_org = getattr(asn_resp, "autonomous_system_organization", None)
            asn = f"AS{asn_number}" if asn_number is not None else None
            org = asn_org or org
            raw["asn"] = {
                "asn": asn,
                "asn_org": asn_org,
            }

    return {
        "country": country,
        "region": region,
        "city": city,
        "loc": loc,
        "org": org,
        "asn": asn,
        "asn_org": asn_org,
        "provider": GEOIP_PROVIDER_MAXMIND,
        "data": raw,
    }
