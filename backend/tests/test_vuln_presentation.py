from datetime import datetime, timedelta, timezone

from app.features.vuln.presentation import serialize_finding, serialize_risk_item


def test_serialize_finding_derives_operational_context() -> None:
    now = datetime.now(timezone.utc)
    row = {
        "id": 42,
        "scan_id": 9,
        "asset_key": "agent:alpha",
        "asset_agent_id": "alpha",
        "reporter_agent_id": "alpha",
        "target": "host-alpha",
        "asset": {
            "package": {
                "name": "openssl",
                "version": "1.1.1u",
                "manager": "apt",
                "ecosystem": "deb",
            },
            "exposure": {
                "has_exposed_ports": True,
                "exposed_ports": [443],
                "service_hints": ["https", "nginx"],
                "surface_score": 72,
            },
        },
        "source": "osv",
        "external_id": "OSV-2024-0001",
        "fingerprint": "fp-1",
        "severity": "critical",
        "severity_rank": 4,
        "confidence": 96,
        "title": "TLS parsing issue",
        "description": "Parsing crafted input can lead to memory corruption.",
        "remediation": "Upgrade openssl from 1.1.1u to 3.0.15 or later.",
        "cve": "CVE-2024-9999",
        "cwe": "CWE-416",
        "cvss": "9.8",
        "location": "pkg:openssl",
        "tags": ["package", "osv"],
        "evidence": {
            "osv": {"fixed": "3.0.15"},
            "analysis": {
                "package_network_facing": True,
                "network_attack_vector": True,
                "exposure_score": 72,
            },
        },
        "status": "open",
        "is_suppressed": False,
        "observation_state": "observed",
        "operator_disposition": "open",
        "first_seen_at": now - timedelta(days=3),
        "last_seen_at": now - timedelta(hours=4),
        "occurrences": 5,
        "updated_at": now,
    }

    finding = serialize_finding(row)

    assert finding["component"]["name"] == "openssl"
    assert finding["component"]["installed_version"] == "1.1.1u"
    assert finding["component"]["fixed_version"] == "3.0.15"
    assert finding["exposure"]["source"] == "observed"
    assert finding["exposure"]["externally_exposed"] is True
    assert finding["asset_display"] == "agent:alpha"
    assert finding["repeated_observation"] is True
    assert finding["remediation_guidance"] == "Upgrade openssl from 1.1.1u to 3.0.15 or later."
    assert "externally exposed asset" in finding["priority"]["factors"]
    assert "fix available" in finding["priority"]["factors"]
    assert finding["priority"]["score"] > 70
    assert "externally reachable services" in str(finding["risk_summary"])

    risk_item = serialize_risk_item(row)
    assert risk_item["component_name"] == "openssl"
    assert risk_item["fixed_version"] == "3.0.15"
    assert risk_item["asset_display"] == "agent:alpha"
    assert risk_item["exposure_source"] == "observed"
    assert risk_item["has_fix"] is True


def test_serialize_finding_distinguishes_inferred_and_resolved_states() -> None:
    now = datetime.now(timezone.utc)
    row = {
        "id": 77,
        "asset_key": "ip:10.0.0.8",
        "asset_agent_id": None,
        "reporter_agent_id": "scanner-1",
        "target": "10.0.0.8",
        "asset": {
            "component": {
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "ecosystem": "maven",
            }
        },
        "source": "osv",
        "external_id": "OSV-2024-7777",
        "fingerprint": "fp-2",
        "severity": "high",
        "severity_rank": 3,
        "confidence": 88,
        "title": "JNDI lookup issue",
        "description": "Lookup handling can trigger remote code execution in exposed services.",
        "remediation": None,
        "cve": "CVE-2021-44228",
        "cwe": None,
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "location": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "tags": ["sbom", "appdep"],
        "evidence": {
            "osv": {"fixed": "2.17.1"},
            "analysis": {
                "package_network_facing": False,
                "network_attack_vector": True,
                "exposure_score": 40,
            },
        },
        "status": "resolved",
        "is_suppressed": False,
        "observation_state": "resolved",
        "operator_disposition": "accepted_risk",
        "first_seen_at": now - timedelta(days=30),
        "last_seen_at": now - timedelta(days=2),
        "occurrences": 2,
        "updated_at": now,
    }

    finding = serialize_finding(row)

    assert finding["component"]["kind"] == "component"
    assert finding["component"]["fixed_version"] == "2.17.1"
    assert finding["exposure"]["source"] == "inferred"
    assert finding["exposure"]["externally_exposed"] is False
    assert "no longer observed" in finding["priority"]["factors"]
    assert "risk accepted" in finding["priority"]["factors"]
    assert finding["priority"]["score"] < 70
