from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional, Tuple

import pytest

from app.shared.indexing.es_mapping import event_index_mapping_properties
from app.workers.indexing import es_bootstrap
from app.workers.indexing.es_bootstrap import (
    bootstrap,
    load_config,
    load_index_template_document,
    render_ilm_policy,
    render_index_template,
)

_ES_ENV_KEYS = [
    "SEAGULL_ES_INDEX_PREFIX",
    "SEAGULL_ES_WRITE_ALIAS",
    "SEAGULL_ES_ROLLOVER_INDEX_PREFIX",
    "SEAGULL_ES_ILM_POLICY_NAME",
    "SEAGULL_ES_TEMPLATE_PRIORITY",
    "SEAGULL_ES_NUMBER_OF_SHARDS",
    "SEAGULL_ES_NUMBER_OF_REPLICAS",
    "SEAGULL_ES_REFRESH_INTERVAL",
    "SEAGULL_ES_ILM_ENABLED",
    "SEAGULL_ES_ILM_DELETE_AFTER_DAYS",
    "SEAGULL_ES_ILM_ROLLOVER_MAX_PRIMARY_SHARD_SIZE",
    "SEAGULL_ES_ILM_ROLLOVER_MAX_AGE",
    "SEAGULL_ES_ILM_WARM_AFTER",
    "SEAGULL_ES_ILM_COLD_AFTER",
    "SEAGULL_ES_ILM_WARM_SHRINK_SHARDS",
    "SEAGULL_ES_ILM_FORCEMERGE_SEGMENTS",
    "SEAGULL_ES_ARTIFACTS_DIR",
]


def _clear_es_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _ES_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(key.replace("SEAGULL_", "NETWATCH_", 1), raising=False)


class _FakeIndices:
    def __init__(self, aliases: Optional[List[str]] = None, indices: Optional[List[str]] = None) -> None:
        self.calls: List[Tuple[Any, ...]] = []
        self._aliases = set(aliases or [])
        self._indices = set(indices or [])
        self.templates: Dict[str, Any] = {}

    def exists_alias(self, name: str) -> bool:
        self.calls.append(("exists_alias", name))
        return name in self._aliases

    def exists(self, index: str) -> bool:
        self.calls.append(("exists", index))
        return index in self._indices or index in self._aliases

    def create(self, index: str, body: Optional[Dict[str, Any]] = None) -> None:
        self.calls.append(("create", index, body))
        self._indices.add(index)
        for alias in ((body or {}).get("aliases") or {}):
            self._aliases.add(alias)

    def put_alias(self, index: str, name: str, body: Optional[Dict[str, Any]] = None) -> None:
        self.calls.append(("put_alias", index, name, body))
        self._aliases.add(name)

    def put_index_template(self, name: str, body: Optional[Dict[str, Any]] = None) -> None:
        self.calls.append(("put_index_template", name, body))
        self.templates[name] = body

    def get(self, index: str) -> Dict[str, Any]:
        self.calls.append(("get", index))
        return {name: {} for name in self._indices if fnmatch.fnmatch(name, index)}

    def put_mapping(self, index: str, properties: Optional[Dict[str, Any]] = None) -> None:
        self.calls.append(("put_mapping", index, properties))


class _FakeIlm:
    def __init__(self, fail: bool = False) -> None:
        self.calls: List[Tuple[Any, ...]] = []
        self.fail = fail
        self.policies: Dict[str, Any] = {}

    def put_lifecycle(self, name: str, body: Optional[Dict[str, Any]] = None) -> None:
        self.calls.append(("put_lifecycle", name, body))
        if self.fail:
            raise RuntimeError("ilm boom")
        self.policies[name] = body


class _FakeES:
    def __init__(self, *, aliases: Optional[List[str]] = None, indices: Optional[List[str]] = None, ilm_fail: bool = False) -> None:
        self.indices = _FakeIndices(aliases=aliases, indices=indices)
        self.ilm = _FakeIlm(fail=ilm_fail)


def _count(calls: List[Tuple[Any, ...]], op: str) -> int:
    return sum(1 for c in calls if c[0] == op)


def test_config_defaults_derive_from_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "seagull-events")

    cfg = load_config()

    assert cfg.write_alias == "seagull-events-write"
    assert cfg.rollover_index_prefix == "seagull-events-ilm"
    assert cfg.ilm_policy_name == "seagull-events-ilm"
    assert cfg.number_of_shards == 1
    assert cfg.number_of_replicas == 0
    assert cfg.refresh_interval == "10s"
    assert cfg.template_priority == 200
    assert cfg.ilm_enabled is True
    assert cfg.ilm_delete_after_days == 90
    assert cfg.ilm_warm_shrink_shards == 0


def test_config_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "custom")
    monkeypatch.setenv("SEAGULL_ES_WRITE_ALIAS", "custom-hot")
    monkeypatch.setenv("SEAGULL_ES_ROLLOVER_INDEX_PREFIX", "custom-rolled")
    monkeypatch.setenv("SEAGULL_ES_NUMBER_OF_SHARDS", "3")
    monkeypatch.setenv("SEAGULL_ES_NUMBER_OF_REPLICAS", "1")
    monkeypatch.setenv("SEAGULL_ES_REFRESH_INTERVAL", "30s")
    monkeypatch.setenv("SEAGULL_ES_ILM_DELETE_AFTER_DAYS", "45")
    monkeypatch.setenv("SEAGULL_ES_ILM_WARM_SHRINK_SHARDS", "1")

    cfg = load_config()

    assert cfg.write_alias == "custom-hot"
    assert cfg.rollover_index_prefix == "custom-rolled"
    assert cfg.ilm_policy_name == "custom-ilm"
    assert cfg.number_of_shards == 3
    assert cfg.number_of_replicas == 1
    assert cfg.refresh_interval == "30s"
    assert cfg.ilm_delete_after_days == 45
    assert cfg.ilm_warm_shrink_shards == 1


def test_template_json_matches_python_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    cfg = load_config()
    doc = load_index_template_document(cfg)
    mappings = doc["template"]["mappings"]

    assert mappings["dynamic"] == "strict"
    assert mappings["properties"] == event_index_mapping_properties()
    assert mappings["properties"]["extra"] == {"type": "flattened"}
    assert mappings["properties"]["extra_search"] == {"type": "text", "norms": False}
    assert set(mappings["runtime"].keys()) == {"dst_port_class", "proto_category"}


def test_render_index_template_applies_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "foo")
    monkeypatch.setenv("SEAGULL_ES_NUMBER_OF_SHARDS", "3")
    monkeypatch.setenv("SEAGULL_ES_NUMBER_OF_REPLICAS", "1")
    monkeypatch.setenv("SEAGULL_ES_REFRESH_INTERVAL", "30s")
    monkeypatch.setenv("SEAGULL_ES_TEMPLATE_PRIORITY", "250")
    cfg = load_config()

    name, body = render_index_template(cfg, attach_ilm=True)
    idx = body["template"]["settings"]["index"]

    assert name == "foo-template"
    assert body["index_patterns"] == ["foo-ilm-*"]
    assert body["priority"] == 250
    assert idx["number_of_shards"] == 3
    assert idx["number_of_replicas"] == 1
    assert idx["refresh_interval"] == "30s"
    assert idx["lifecycle"] == {"name": "foo-ilm", "rollover_alias": "foo-write"}
    assert body["template"]["mappings"]["dynamic"] == "strict"

    _name2, body_noilm = render_index_template(cfg, attach_ilm=False)
    assert "lifecycle" not in body_noilm["template"]["settings"]["index"]


def test_render_ilm_policy_applies_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "foo")
    monkeypatch.setenv("SEAGULL_ES_ILM_ROLLOVER_MAX_PRIMARY_SHARD_SIZE", "10gb")
    monkeypatch.setenv("SEAGULL_ES_ILM_ROLLOVER_MAX_AGE", "6h")
    monkeypatch.setenv("SEAGULL_ES_ILM_WARM_AFTER", "2d")
    monkeypatch.setenv("SEAGULL_ES_ILM_COLD_AFTER", "10d")
    monkeypatch.setenv("SEAGULL_ES_ILM_DELETE_AFTER_DAYS", "45")
    monkeypatch.setenv("SEAGULL_ES_ILM_FORCEMERGE_SEGMENTS", "2")
    monkeypatch.setenv("SEAGULL_ES_ILM_WARM_SHRINK_SHARDS", "2")
    cfg = load_config()

    name, body = render_ilm_policy(cfg)
    phases = body["policy"]["phases"]

    assert name == "foo-ilm"
    assert phases["hot"]["actions"]["rollover"] == {"max_primary_shard_size": "10gb", "max_age": "6h"}
    assert phases["warm"]["min_age"] == "2d"
    assert phases["warm"]["actions"]["forcemerge"]["max_num_segments"] == 2
    assert phases["warm"]["actions"]["shrink"] == {"number_of_shards": 2}
    assert phases["cold"]["min_age"] == "10d"
    assert phases["delete"]["min_age"] == "45d"


def test_render_ilm_policy_shrink_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_ILM_WARM_SHRINK_SHARDS", "0")
    cfg = load_config()

    _name, body = render_ilm_policy(cfg)
    assert "shrink" not in body["policy"]["phases"]["warm"]["actions"]


def test_bootstrap_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    cfg = load_config()
    es = _FakeES()

    bootstrap(es, cfg)

    assert _count(es.ilm.calls, "put_lifecycle") == 1
    assert es.ilm.policies["seagull-events-ilm"] is not None
    assert _count(es.indices.calls, "put_index_template") == 1
    creates = [c for c in es.indices.calls if c[0] == "create"]
    assert len(creates) == 1
    assert creates[0][1] == "seagull-events-ilm-000001"
    assert creates[0][2]["aliases"] == {"seagull-events-write": {"is_write_index": True}}
    # Template attached ILM because the policy applied.
    template_body = es.indices.templates["seagull-events-template"]
    assert template_body["template"]["settings"]["index"]["lifecycle"]["rollover_alias"] == "seagull-events-write"

    bootstrap(es, cfg)
    # Write index already bootstrapped -> no second create.
    assert len([c for c in es.indices.calls if c[0] == "create"]) == 1


def test_bootstrap_without_ilm(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    monkeypatch.setenv("SEAGULL_ES_ILM_ENABLED", "false")
    cfg = load_config()
    es = _FakeES()

    bootstrap(es, cfg)

    assert _count(es.ilm.calls, "put_lifecycle") == 0
    template_body = es.indices.templates["seagull-events-template"]
    assert "lifecycle" not in template_body["template"]["settings"]["index"]


def test_bootstrap_policy_failure_detaches_ilm_from_template(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    cfg = load_config()
    es = _FakeES(ilm_fail=True)

    bootstrap(es, cfg)

    assert _count(es.ilm.calls, "put_lifecycle") == 1
    template_body = es.indices.templates["seagull-events-template"]
    assert "lifecycle" not in template_body["template"]["settings"]["index"]
    # Write index still bootstrapped so indexing keeps working.
    assert any(c[0] == "create" for c in es.indices.calls)


def test_write_index_skipped_when_alias_name_is_concrete_index(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_es_env(monkeypatch)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    cfg = load_config()
    es = _FakeES(indices=["seagull-events-write"])

    es_bootstrap.ensure_write_index(es, cfg)

    assert not any(c[0] == "create" for c in es.indices.calls)
    assert not any(c[0] == "put_alias" for c in es.indices.calls)
