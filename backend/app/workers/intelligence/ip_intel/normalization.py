from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.config.env_secrets import getenv_compat

GEOIP_PROVIDER_AUTO = "auto"
GEOIP_PROVIDER_MAXMIND = "maxmind_local"
GEOIP_PROVIDER_IPINFO = "ipinfo"
GEOIP_PROVIDER_NONE = "none"

ASN_RE = re.compile(r"^(AS\d+)\s+(.*)$")


def _env_raw(*names: str) -> Optional[str]:
    for name in names:
        raw = getenv_compat(name)
        if raw is None:
            continue
        value = raw.strip()
        if value == "":
            continue
        return value
    return None


def _env_str(default: str, *names: str) -> str:
    value = _env_raw(*names)
    return value if value is not None else default


def _env_int(default: int, *names: str) -> int:
    value = _env_raw(*names)
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _env_float(default: float, *names: str) -> float:
    value = _env_raw(*names)
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_public_ip(ip: str) -> bool:
    from app.shared.network.ip_classification import classify_ip
    return classify_ip(ip)["scope"] == "public_internet"


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        out[k] = v
    return out


def _parse_asn(org: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not org:
        return None, None
    m = ASN_RE.match(org.strip())
    if not m:
        return None, org.strip()
    return m.group(1), m.group(2).strip()
