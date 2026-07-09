from __future__ import annotations

import copy
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.config.env_secrets import env_value
from app.core.observability import log_event
from app.shared.indexing.es_mapping import event_index_mapping_properties

logger = logging.getLogger("seagull.worker.es_indexer")

INDEX_TEMPLATE_FILENAME = "index-template.json"
ILM_POLICY_FILENAME = "ilm-policy.json"

_CONTAINER_ARTIFACTS_DIR = "/etc/seagull/elasticsearch"


def _env_str(name: str, default: Optional[str] = None) -> Optional[str]:
    return env_value(name, default)


def _env_int(name: str, default: int) -> int:
    v = _env_str(name)
    if v is None:
        return default
    try:
        return int(v, 10)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    v = _env_str(name)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


@dataclass(frozen=True)
class ESConfig:
    url: str
    index_prefix: str
    batch_size: int
    every_seconds: float
    idle_sleep_seconds: float
    request_timeout_seconds: int
    bootstrap: bool
    artifacts_dir: str
    write_alias: str
    rollover_index_prefix: str
    template_priority: int
    number_of_shards: int
    number_of_replicas: int
    refresh_interval: str
    tier_preference: str
    ilm_enabled: bool
    ilm_migrate_enabled: bool
    ilm_policy_name: str
    ilm_rollover_max_primary_shard_size: str
    ilm_rollover_max_age: str
    ilm_warm_after: str
    ilm_cold_after: str
    ilm_delete_after_days: int
    ilm_warm_shrink_shards: int
    ilm_forcemerge_segments: int
    username: Optional[str]
    password: Optional[str]
    verify_certs: bool
    ca_certs: Optional[str]


def _tier_preference_from_env() -> str:
    raw = (_env_str("SEAGULL_ES_TIER_PREFERENCE", "data_hot") or "data_hot").strip()
    return "" if raw.lower() == "none" else raw


def load_config() -> ESConfig:
    prefix = _env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events") or "seagull-events"
    ilm_policy_name = _env_str("SEAGULL_ES_ILM_POLICY_NAME", "") or ""
    write_alias = _env_str("SEAGULL_ES_WRITE_ALIAS", "") or ""
    rollover_index_prefix = _env_str("SEAGULL_ES_ROLLOVER_INDEX_PREFIX", "") or ""
    return ESConfig(
        url=_env_str("SEAGULL_ES_URL", "http://elasticsearch:9200") or "http://elasticsearch:9200",
        index_prefix=prefix,
        batch_size=max(1, _env_int("SEAGULL_ES_BATCH_SIZE", 500)),
        every_seconds=max(0.1, _env_float("SEAGULL_ES_EVERY_SECONDS", 1.0)),
        idle_sleep_seconds=max(0.25, _env_float("SEAGULL_ES_IDLE_SLEEP_SECONDS", 2.0)),
        request_timeout_seconds=max(5, _env_int("SEAGULL_ES_REQUEST_TIMEOUT_SECONDS", 30)),
        bootstrap=_env_bool("SEAGULL_ES_BOOTSTRAP", False),
        artifacts_dir=_env_str("SEAGULL_ES_ARTIFACTS_DIR", "") or "",
        write_alias=write_alias or f"{prefix}-write",
        rollover_index_prefix=rollover_index_prefix or f"{prefix}-ilm",
        template_priority=_env_int("SEAGULL_ES_TEMPLATE_PRIORITY", 200),
        number_of_shards=max(1, _env_int("SEAGULL_ES_NUMBER_OF_SHARDS", 1)),
        number_of_replicas=max(0, _env_int("SEAGULL_ES_NUMBER_OF_REPLICAS", 0)),
        refresh_interval=_env_str("SEAGULL_ES_REFRESH_INTERVAL", "10s") or "10s",
        tier_preference=_tier_preference_from_env(),
        ilm_enabled=_env_bool("SEAGULL_ES_ILM_ENABLED", True),
        ilm_migrate_enabled=_env_bool("SEAGULL_ES_ILM_MIGRATE_ENABLED", False),
        ilm_policy_name=ilm_policy_name or f"{prefix}-ilm",
        ilm_rollover_max_primary_shard_size=_env_str("SEAGULL_ES_ILM_ROLLOVER_MAX_PRIMARY_SHARD_SIZE", "50gb") or "50gb",
        ilm_rollover_max_age=_env_str("SEAGULL_ES_ILM_ROLLOVER_MAX_AGE", "1d") or "1d",
        ilm_warm_after=_env_str("SEAGULL_ES_ILM_WARM_AFTER", "3d") or "3d",
        ilm_cold_after=_env_str("SEAGULL_ES_ILM_COLD_AFTER", "14d") or "14d",
        ilm_delete_after_days=max(1, _env_int("SEAGULL_ES_ILM_DELETE_AFTER_DAYS", 90)),
        ilm_warm_shrink_shards=max(0, _env_int("SEAGULL_ES_ILM_WARM_SHRINK_SHARDS", 0)),
        ilm_forcemerge_segments=max(1, _env_int("SEAGULL_ES_ILM_FORCEMERGE_SEGMENTS", 1)),
        username=_env_str("SEAGULL_ES_USERNAME", None),
        password=_env_str("SEAGULL_ES_PASSWORD", None),
        verify_certs=_env_bool("SEAGULL_ES_VERIFY_CERTS", True),
        ca_certs=_env_str("SEAGULL_ES_CA_CERTS", None),
    )


def resolve_artifacts_dir(configured: Optional[str]) -> Path:
    candidates: List[Path] = []
    if configured and configured.strip():
        candidates.append(Path(configured.strip()))
    candidates.append(Path(_CONTAINER_ARTIFACTS_DIR))
    candidates.append(Path(__file__).resolve().parents[4] / "infra" / "elasticsearch")

    for candidate in candidates:
        if (candidate / INDEX_TEMPLATE_FILENAME).is_file():
            return candidate
    searched = ", ".join(str(c) for c in candidates)
    raise FileNotFoundError(f"Elasticsearch artifacts not found (looked in: {searched})")


def _load_artifact(filename: str, cfg: ESConfig) -> Dict[str, Any]:
    path = resolve_artifacts_dir(cfg.artifacts_dir) / filename
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_index_template_document(cfg: ESConfig) -> Dict[str, Any]:
    return _load_artifact(INDEX_TEMPLATE_FILENAME, cfg)


def load_ilm_policy_document(cfg: ESConfig) -> Dict[str, Any]:
    return _load_artifact(ILM_POLICY_FILENAME, cfg)


def render_ilm_policy(cfg: ESConfig) -> Tuple[str, Dict[str, Any]]:
    body = copy.deepcopy(load_ilm_policy_document(cfg))
    phases = body["policy"]["phases"]

    rollover = phases["hot"]["actions"]["rollover"]
    rollover["max_primary_shard_size"] = cfg.ilm_rollover_max_primary_shard_size
    rollover["max_age"] = cfg.ilm_rollover_max_age

    warm = phases["warm"]
    warm["min_age"] = cfg.ilm_warm_after
    warm["actions"]["forcemerge"]["max_num_segments"] = cfg.ilm_forcemerge_segments
    if cfg.ilm_warm_shrink_shards > 0:
        warm["actions"]["shrink"] = {"number_of_shards": cfg.ilm_warm_shrink_shards}
    else:
        warm["actions"].pop("shrink", None)

    phases["cold"]["min_age"] = cfg.ilm_cold_after
    phases["delete"]["min_age"] = f"{cfg.ilm_delete_after_days}d"

    # Dropping the explicit opt-out re-enables ILM's default tier migration.
    if cfg.ilm_migrate_enabled:
        for phase in ("warm", "cold"):
            phases.get(phase, {}).get("actions", {}).pop("migrate", None)

    return cfg.ilm_policy_name, body


def render_index_template(cfg: ESConfig, *, attach_ilm: bool) -> Tuple[str, Dict[str, Any]]:
    body = copy.deepcopy(load_index_template_document(cfg))
    body["index_patterns"] = [f"{cfg.rollover_index_prefix}-*"]
    body["priority"] = cfg.template_priority

    index_settings = body["template"].setdefault("settings", {}).setdefault("index", {})
    index_settings["number_of_shards"] = cfg.number_of_shards
    index_settings["number_of_replicas"] = cfg.number_of_replicas
    index_settings["refresh_interval"] = cfg.refresh_interval
    if cfg.tier_preference:
        index_settings["routing"] = {"allocation": {"include": {"_tier_preference": cfg.tier_preference}}}
    else:
        index_settings.pop("routing", None)
    if attach_ilm:
        index_settings["lifecycle"] = {"name": cfg.ilm_policy_name, "rollover_alias": cfg.write_alias}
    else:
        index_settings.pop("lifecycle", None)

    return f"{cfg.index_prefix}-template", body


def ensure_ilm_policy(es: Any, cfg: ESConfig) -> bool:
    if not cfg.ilm_enabled:
        log_event(logger, "info", "es_ilm_disabled")
        return False
    name, body = render_ilm_policy(cfg)
    try:
        es.ilm.put_lifecycle(name=name, body=body)
    except Exception as e:
        log_event(logger, "warning", "es_ilm_policy_error", policy=name, error_type=type(e).__name__)
        return False
    log_event(logger, "info", "es_ilm_policy_applied", policy=name)
    return True


def ensure_index_template(es: Any, cfg: ESConfig, *, attach_ilm: bool) -> None:
    name, body = render_index_template(cfg, attach_ilm=attach_ilm)
    version = (body.get("_meta") or {}).get("version")
    es.indices.put_index_template(name=name, body=body)
    log_event(
        logger,
        "info",
        "es_index_template_applied",
        template=name,
        version=version,
        patterns=body["index_patterns"],
        ilm=attach_ilm,
    )


def ensure_write_index(es: Any, cfg: ESConfig) -> None:
    write_alias = cfg.write_alias
    bootstrap_index = f"{cfg.rollover_index_prefix}-000001"

    try:
        if es.indices.exists_alias(name=write_alias):
            log_event(logger, "info", "es_write_alias_present", alias=write_alias)
            return
    except Exception as e:
        log_event(logger, "warning", "es_write_alias_check_error", alias=write_alias, error_type=type(e).__name__)
        return

    try:
        if es.indices.exists(index=write_alias):
            log_event(logger, "warning", "es_write_alias_name_is_index", alias=write_alias)
            return
    except Exception:
        pass

    try:
        if es.indices.exists(index=bootstrap_index):
            es.indices.put_alias(index=bootstrap_index, name=write_alias, body={"is_write_index": True})
        else:
            es.indices.create(index=bootstrap_index, body={"aliases": {write_alias: {"is_write_index": True}}})
    except Exception as e:
        log_event(logger, "warning", "es_write_index_bootstrap_error", index=bootstrap_index, error_type=type(e).__name__)
        return
    log_event(logger, "info", "es_write_index_bootstrapped", index=bootstrap_index, alias=write_alias)


def reconcile_existing_index_mappings(es: Any, cfg: ESConfig) -> None:
    # Templates only apply to indices created afterwards. Add the declared fields
    # to pre-existing indices too; indices where a field was already dynamic-mapped
    # with a conflicting type reject the update (they heal on rollover) — best
    # effort, never fatal.
    try:
        indices = list(es.indices.get(index=f"{cfg.index_prefix}-*") or {})
    except Exception as e:
        log_event(logger, "warning", "es_mapping_reconcile_list_error", error_type=type(e).__name__)
        return
    properties = event_index_mapping_properties()
    updated = 0
    skipped = 0
    for index in indices:
        try:
            es.indices.put_mapping(index=index, properties=properties)
            updated += 1
        except Exception:
            skipped += 1
    if updated or skipped:
        log_event(logger, "info", "es_mapping_reconcile_done", updated=updated, skipped=skipped)


def bootstrap(es: Any, cfg: ESConfig) -> None:
    policy_ok = ensure_ilm_policy(es, cfg)
    attach_ilm = bool(cfg.ilm_enabled and policy_ok)
    if cfg.ilm_enabled and not policy_ok:
        log_event(logger, "warning", "es_ilm_unavailable_template_without_ilm", policy=cfg.ilm_policy_name)
    ensure_index_template(es, cfg, attach_ilm=attach_ilm)
    ensure_write_index(es, cfg)
    reconcile_existing_index_mappings(es, cfg)
