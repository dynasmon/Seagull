"""IP intel skip behavior: non-public IPs are skipped and carry classification metadata."""
from __future__ import annotations

import pytest

from app.shared.network.ip_classification import classify_ip
from app.workers.intelligence.ip_intel.normalization import _is_public_ip


@pytest.mark.parametrize("ip", ["10.0.0.1", "172.16.1.1", "192.168.1.1"])
def test_is_public_ip_false_for_rfc1918(ip):
    assert not _is_public_ip(ip)


def test_is_public_ip_false_for_loopback():
    assert not _is_public_ip("127.0.0.1")


def test_is_public_ip_false_for_link_local():
    assert not _is_public_ip("169.254.0.1")


def test_is_public_ip_false_for_cgnat():
    assert not _is_public_ip("100.64.0.1")


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "104.21.0.1"])
def test_is_public_ip_true_for_public(ip):
    assert _is_public_ip(ip)


def test_skip_patch_metadata_private():
    """The skip patch for a private IP carries scope/label/is_internal/is_public."""
    cls = classify_ip("192.168.1.1")
    patch = {
        "lupe_skipped": True,
        "lupe_reason": "non_public_ip",
        "src_ip_scope": cls["scope"],
        "src_ip_label": cls["label"],
        "src_is_internal": cls["is_internal"],
        "src_is_public": cls["is_public"],
    }
    assert patch["src_ip_scope"] == "private_address"
    assert patch["src_ip_label"] == "Private"
    assert patch["src_is_internal"] is True
    assert patch["src_is_public"] is False


def test_skip_patch_metadata_loopback():
    cls = classify_ip("127.0.0.1")
    assert cls["scope"] == "loopback"
    assert cls["is_internal"] is True
    assert not cls["is_public"]


def test_skip_patch_metadata_link_local():
    cls = classify_ip("169.254.100.1")
    assert cls["scope"] == "link_local"
    assert cls["is_internal"] is True
    assert not cls["is_public"]


def test_skip_patch_metadata_cgnat():
    cls = classify_ip("100.64.1.1")
    assert cls["scope"] == "cgnat"
    assert cls["is_internal"] is True
    assert not cls["is_public"]


def test_public_ip_would_not_be_skipped():
    """Public IPs are not skipped — they proceed to geo enrichment."""
    cls = classify_ip("8.8.8.8")
    assert cls["is_public"] is True
    assert cls["scope"] == "public_internet"
