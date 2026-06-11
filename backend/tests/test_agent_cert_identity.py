import pytest
from fastapi import HTTPException

from app.features.agents import auth


class _StubRequest:
    def __init__(self, headers):
        self.headers = headers


def _req(cn=None):
    headers = {}
    if cn is not None:
        headers["X-Agent-Cert-CN"] = cn
    return _StubRequest(headers)


class TestExtractCertCn:
    def test_rfc4514_cn_first(self):
        assert auth._extract_cert_cn(_req("CN=agent-core-1,O=Seagull Agents")) == "agent-core-1"

    def test_cn_last(self):
        assert auth._extract_cert_cn(_req("O=Seagull Agents,CN=agent-core-1")) == "agent-core-1"

    def test_spaces_tolerated(self):
        assert auth._extract_cert_cn(_req("O = Seagull Agents, CN = agent-ddos-1")) == "agent-ddos-1"

    def test_absent_header(self):
        assert auth._extract_cert_cn(_req(None)) is None

    def test_empty_header(self):
        assert auth._extract_cert_cn(_req("   ")) is None


class TestEnforceCertIdentity:
    def test_off_ignores_mismatch(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_IDENTITY_BINDING", "off")
        auth._enforce_cert_identity(_req("CN=agent-evil"), "agent-core-1")

    def test_warn_allows_mismatch(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_IDENTITY_BINDING", "warn")
        auth._enforce_cert_identity(_req("CN=agent-evil,O=Seagull Agents"), "agent-core-1")

    def test_enforce_rejects_mismatch(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_IDENTITY_BINDING", "enforce")
        with pytest.raises(HTTPException) as exc:
            auth._enforce_cert_identity(_req("CN=agent-evil,O=Seagull Agents"), "agent-core-1")
        assert exc.value.status_code == 403

    def test_enforce_allows_match(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_IDENTITY_BINDING", "enforce")
        auth._enforce_cert_identity(_req("CN=agent-core-1,O=Seagull Agents"), "agent-core-1")

    def test_enforce_rejects_absent_header(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_IDENTITY_BINDING", "enforce")
        with pytest.raises(HTTPException) as exc:
            auth._enforce_cert_identity(_req(None), "agent-core-1")
        assert exc.value.status_code == 403

    def test_warn_allows_absent_header(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_IDENTITY_BINDING", "warn")
        auth._enforce_cert_identity(_req(None), "agent-core-1")
