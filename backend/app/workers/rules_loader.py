from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import re

import yaml

from app.core.config import settings

_VERSION_RE = re.compile(r"_v(\d+)$", re.IGNORECASE)


def _rules_dir_path(rules_dir: str | Path | None = None) -> Path:
    if rules_dir is not None:
        return Path(rules_dir).resolve()
    return Path(getattr(settings, "NETWATCH_RULES_DIR", "/app/rules") or "/app/rules").resolve()


def _discover_rule_files(rules_dir: Path) -> List[Path]:
    files: list[Path] = []
    for pat in ("*.yml", "*.yaml", "**/*.yml", "**/*.yaml"):
        for p in rules_dir.glob(pat):
            if p.is_file():
                files.append(p)
    # de-dup + deterministic order
    uniq = sorted({p.resolve() for p in files})
    return [Path(p) for p in uniq]


def _parse_rule_version(rule_id: str, explicit_version: Any = None) -> int:
    if explicit_version is not None:
        try:
            return max(1, int(explicit_version))
        except Exception:
            pass
    m = _VERSION_RE.search(str(rule_id or "").strip())
    if m:
        try:
            return max(1, int(m.group(1)))
        except Exception:
            pass
    return 1


def _normalize_rule(
    *,
    raw_rule: Dict[str, Any],
    file_meta: Dict[str, Any],
    source_file: str,
    with_source: bool,
) -> Optional[Dict[str, Any]]:
    rid = str(raw_rule.get("id") or "").strip()
    if not rid:
        return None

    r = dict(raw_rule)
    r["pack"] = str(r.get("pack") or file_meta.get("pack") or "").strip() or None
    r["category"] = str(r.get("category") or file_meta.get("category") or "").strip() or None
    r["pack_version"] = int(file_meta.get("pack_version") or 1)
    r["rule_version"] = _parse_rule_version(rid, r.get("version"))
    r["schema_version"] = int(file_meta.get("schema_version") or 1)

    # Base blocks for tuning/suppressions, can be extended by DB overrides.
    sup = r.get("suppressions")
    r["suppressions"] = sup if isinstance(sup, list) else []
    tun = r.get("tuning")
    r["tuning"] = tun if isinstance(tun, dict) else {}

    if with_source:
        r["source_file"] = source_file
    return r


def _iter_rules_from_file(path: Path, rules_dir: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        return []
    file_rules = data.get("rules", [])
    if not isinstance(file_rules, list):
        return []

    file_meta = {
        "pack": data.get("pack"),
        "category": data.get("category"),
        "pack_version": data.get("pack_version", 1),
        "schema_version": data.get("schema_version", 1),
    }
    source_file = str(path.relative_to(rules_dir))

    out: list[Dict[str, Any]] = []
    for rule in file_rules:
        if not isinstance(rule, dict):
            continue
        nr = _normalize_rule(
            raw_rule=rule,
            file_meta=file_meta,
            source_file=source_file,
            with_source=True,
        )
        if nr:
            out.append(nr)
    return out


def load_rules(
    *,
    include_disabled: bool = False,
    with_source: bool = False,
    rules_dir: str | Path | None = None,
) -> List[Dict[str, Any]]:
    """Load rules from YAML files under rules dir (recursive).

    Supports both legacy flat layout (`rules/*.yml`) and packs (`rules/packs/**`).
    """

    out: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    base = _rules_dir_path(rules_dir)
    if not base.exists():
        return out

    for path in _discover_rule_files(base):
        for rule in _iter_rules_from_file(path, base):
            rid = str(rule.get("id") or "").strip()
            if not rid:
                continue
            if rid in seen_ids:
                raise RuntimeError(f"Duplicate rule id detected: {rid}")

            enabled = rule.get("enabled", True)
            if (not include_disabled) and (enabled is False):
                continue

            if not with_source:
                rule.pop("source_file", None)

            out.append(rule)
            seen_ids.add(rid)

    out.sort(key=lambda r: (str(r.get("pack") or ""), str(r.get("category") or ""), str(r.get("id") or "")))
    return out
