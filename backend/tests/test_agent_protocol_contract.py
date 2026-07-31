from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.features.agents import protocol
from app.features.agents.schemas import AgentEnrollIn, AgentHeartbeatIn, AgentProtocolOut
from app.features.events.schemas import NetEvent


def test_server_window_is_loaded_from_the_versioned_contract() -> None:
    server = protocol.COMPATIBILITY["server"]
    assert protocol.PROTOCOL_VERSION == protocol.CONTRACT["protocol_version"]
    assert protocol.EVENT_SCHEMA_VERSION == protocol.CONTRACT["event_schema_version"]
    assert protocol.MIN_SUPPORTED_PROTOCOL == server["oldest_supported_agent_protocol"]
    assert protocol.MAX_SUPPORTED_PROTOCOL == server["newest_supported_agent_protocol"]
    assert protocol.MIN_EVENT_SCHEMA == server["accepts_event_schema"]["min"]
    assert protocol.MAX_EVENT_SCHEMA == server["accepts_event_schema"]["max"]


def test_descriptor_matches_the_contract_shape() -> None:
    value = AgentProtocolOut(**protocol.descriptor())
    assert value.protocol_version == protocol.PROTOCOL_VERSION
    assert value.min_supported == protocol.MIN_SUPPORTED_PROTOCOL
    assert value.max_supported == protocol.MAX_SUPPORTED_PROTOCOL
    assert value.min_event_schema == protocol.MIN_EVENT_SCHEMA
    assert value.max_event_schema == protocol.MAX_EVENT_SCHEMA


@pytest.mark.parametrize(
    "version",
    [None, protocol.MIN_SUPPORTED_PROTOCOL, protocol.PROTOCOL_VERSION, protocol.MAX_SUPPORTED_PROTOCOL],
)
def test_supported_protocol_window_accepts_independent_releases(version: int | None) -> None:
    protocol.ensure_supported(version, context="test")


@pytest.mark.parametrize(
    ("version", "kind"),
    [
        (protocol.MIN_SUPPORTED_PROTOCOL - 1, "protocol_version_too_old"),
        (protocol.MAX_SUPPORTED_PROTOCOL + 1, "protocol_version_too_new"),
    ],
)
def test_unsupported_protocol_is_structured_and_safe(version: int, kind: str) -> None:
    with pytest.raises(HTTPException) as exc:
        protocol.ensure_supported(version, context="test")
    assert exc.value.status_code == 426
    assert exc.value.detail["kind"] == kind
    assert exc.value.detail["server_protocol_version"] == protocol.PROTOCOL_VERSION
    assert exc.value.detail["min_supported"] == protocol.MIN_SUPPORTED_PROTOCOL
    assert exc.value.detail["max_supported"] == protocol.MAX_SUPPORTED_PROTOCOL


def test_unsupported_event_schema_is_structured_and_safe() -> None:
    with pytest.raises(HTTPException) as exc:
        protocol.ensure_event_schema(protocol.MAX_EVENT_SCHEMA + 1, context="test")
    assert exc.value.status_code == 426
    assert exc.value.detail["kind"] == "event_schema_unsupported"
    assert exc.value.detail["min_event_schema"] == protocol.MIN_EVENT_SCHEMA
    assert exc.value.detail["max_event_schema"] == protocol.MAX_EVENT_SCHEMA


def test_unknown_optional_fields_and_capabilities_are_accepted() -> None:
    value = AgentHeartbeatIn.model_validate(
        {
            "status": "ok",
            "protocol_version": protocol.PROTOCOL_VERSION,
            "capabilities": {"future_capability": {"version": 2}},
            "future_optional_field": "ignored",
        }
    )
    assert value.capabilities == {"future_capability": {"version": 2}}


def test_response_action_capabilities_are_versioned_in_the_contract() -> None:
    heartbeat = protocol.CONTRACT["$defs"]["HeartbeatRequest"]
    assert heartbeat["properties"]["capabilities"]["$ref"] == "#/$defs/AgentCapabilities"
    capabilities = protocol.CONTRACT["$defs"]["AgentCapabilities"]
    properties = capabilities["properties"]
    assert {"profile", "response_actions", "response_action_types", "shell_exec"} <= set(properties)
    assert capabilities["additionalProperties"] is True


def test_response_action_delivery_states_are_closed() -> None:
    status_schema = protocol.CONTRACT["$defs"]["ResponseAction"]["properties"]["status"]
    assert status_schema["enum"] == ["pending", "delivered"]


def test_agent_identifier_uses_the_contract_pattern() -> None:
    with pytest.raises(ValueError):
        AgentEnrollIn(agent_id="../unsafe")


def test_event_identifier_uses_the_contract_pattern() -> None:
    event_schema = protocol.CONTRACT["$defs"]["NetEvent"]["properties"]["event_id"]
    assert event_schema["minLength"] == 36
    assert event_schema["maxLength"] == 36
    event = NetEvent.model_validate(
        {
            "event_id": "0f6f8f2a-2b0a-4a3f-9d54-0c9b0a2b6f11",
            "agent_id": "agent-contract-1",
            "event_type": "flow",
            "timestamp": "2026-07-30T12:00:00Z",
        }
    )
    assert event.event_id == "0f6f8f2a-2b0a-4a3f-9d54-0c9b0a2b6f11"
    with pytest.raises(ValueError):
        NetEvent.model_validate(
            {
                "event_id": "not-a-stable-event-id",
                "agent_id": "agent-contract-1",
                "event_type": "flow",
                "timestamp": "2026-07-30T12:00:00Z",
            }
        )
