from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import func, select, update

from app.core.db import engine
from app.features.events.models import NetEventModel
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset


def ensure_offset_row(offset_name: str) -> None:
    ensure_offset(offset_name)


def get_last_offset(offset_name: str) -> int:
    return get_offset(offset_name)


def set_last_offset(offset_name: str, last_id: int) -> None:
    set_offset(offset_name, last_id)


def pick_batch_max_event_id(last_id: int, max_rows: int) -> int:
    with engine.begin() as conn:
        row = conn.execute(select(func.max(NetEventModel.id)).where(NetEventModel.id > int(last_id))).fetchone()
        max_id = int(row[0]) if row and row[0] is not None else last_id
    return min(max_id, last_id + max_rows)


def fetch_unprocessed_batch(*, last_id: int, max_id: int, batch_size: int) -> List[Dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            select(
                NetEventModel.id,
                NetEventModel.event_type,
                NetEventModel.proto,
                NetEventModel.src_port,
                NetEventModel.dst_port,
                NetEventModel.extra,
            )
            .where(
                NetEventModel.id > int(last_id),
                NetEventModel.id <= int(max_id),
                ~NetEventModel.extra.has_key("proto_intel_at"),
            )
            .order_by(NetEventModel.id.asc())
            .limit(int(batch_size))
        ).mappings().all()
        return [dict(r) for r in rows]


def patch_event_proto_intel(event_id: int, patch: Dict[str, Any]) -> None:
    def _norm_str(key: str, *, lower: bool = False, upper: bool = False, default: str | None = None) -> str | None:
        raw = patch.get(key)
        if raw is None:
            return default
        value = str(raw).strip()
        if not value:
            return default
        if lower:
            return value.lower()
        if upper:
            return value.upper()
        return value

    values = {
        "extra": NetEventModel.extra.op("||")(patch),
        "app_proto": _norm_str("app_proto"),
        "app_proto_reason": _norm_str("app_proto_reason"),
        "app_proto_conf_band": _norm_str("app_proto_conf_band"),
        "dns_qname": _norm_str("dns_qname", lower=True),
        "http_host": _norm_str("http_host", lower=True),
        "http_method": _norm_str("http_method", upper=True),
        "tls_sni": _norm_str("tls_sni", lower=True),
        "tls_alpn_first": _norm_str("tls_alpn_first", lower=True),
        "ja3": _norm_str("ja3"),
        "ja4": _norm_str("ja4"),
        "ja4_ptype": _norm_str("ja4_ptype", default="t"),
    }
    with engine.begin() as conn:
        conn.execute(
            update(NetEventModel)
            .where(NetEventModel.id == int(event_id))
            .values(**values)
        )
