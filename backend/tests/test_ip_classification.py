from __future__ import annotations

import pytest

from app.shared.network.ip_classification import classify_ip, classify_flow, parse_internal_cidrs


# ---- Output shape ---------------------------------------------------------------

def test_output_has_all_required_keys() -> None:
    r = classify_ip("8.8.8.8")
    for key in ("ip", "version", "scope", "label", "is_internal", "is_public", "is_special", "matched_cidr", "match_source"):
        assert key in r, f"missing key: {key}"


# ---- Public IPv4 ----------------------------------------------------------------

def test_public_ipv4_google_dns() -> None:
    r = classify_ip("8.8.8.8")
    assert r["scope"] == "public_internet"
    assert r["is_public"] is True
    assert r["is_internal"] is False
    assert r["is_special"] is False
    assert r["version"] == 4
    assert r["ip"] == "8.8.8.8"


def test_public_ipv4_cloudflare() -> None:
    r = classify_ip("1.1.1.1")
    assert r["scope"] == "public_internet"
    assert r["is_public"] is True


# ---- RFC1918 private addresses --------------------------------------------------

def test_private_rfc1918_10() -> None:
    r = classify_ip("10.0.0.5")
    assert r["scope"] == "private_address"
    assert r["is_internal"] is True
    assert r["is_public"] is False
    assert r["matched_cidr"] == "10.0.0.0/8"
    assert r["match_source"] == "builtin"


def test_private_rfc1918_172() -> None:
    r = classify_ip("172.16.50.1")
    assert r["scope"] == "private_address"
    assert r["matched_cidr"] == "172.16.0.0/12"


def test_private_rfc1918_172_boundary() -> None:
    r = classify_ip("172.31.255.254")
    assert r["scope"] == "private_address"
    assert r["matched_cidr"] == "172.16.0.0/12"


def test_private_rfc1918_192() -> None:
    r = classify_ip("192.168.1.1")
    assert r["scope"] == "private_address"
    assert r["matched_cidr"] == "192.168.0.0/16"


# ---- Configured internal CIDRs --------------------------------------------------

def test_configured_cidr_overrides_builtin_private() -> None:
    r = classify_ip("10.20.30.40", internal_cidrs=["10.20.30.0/24"])
    assert r["scope"] == "internal_network"
    assert r["match_source"] == "configured_cidr"
    assert r["matched_cidr"] == "10.20.30.0/24"
    assert r["is_internal"] is True
    assert r["label"] == "Internal"


def test_configured_cidr_non_rfc1918_range() -> None:
    r = classify_ip("203.0.113.5", internal_cidrs=["203.0.113.0/24"])
    assert r["scope"] == "internal_network"
    assert r["match_source"] == "configured_cidr"


def test_configured_cidr_no_match_falls_through_to_builtin() -> None:
    r = classify_ip("10.0.0.1", internal_cidrs=["192.168.100.0/24"])
    assert r["scope"] == "private_address"
    assert r["match_source"] == "builtin"


def test_configured_cidr_multiple_cidrs_second_matches() -> None:
    r = classify_ip("172.20.5.1", internal_cidrs=["10.100.0.0/16", "172.20.0.0/14"])
    assert r["scope"] == "internal_network"
    assert r["match_source"] == "configured_cidr"


def test_invalid_cidr_ignored_valid_still_works(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        r = classify_ip("10.0.0.1", internal_cidrs=["not-a-cidr", "10.0.0.0/8"])
    assert r["scope"] == "internal_network"
    assert any("not-a-cidr" in record.message for record in caplog.records)


def test_all_invalid_cidrs_falls_back_gracefully(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        r = classify_ip("10.0.0.1", internal_cidrs=["bad", "also-bad"])
    assert r["scope"] == "private_address"


# ---- Loopback -------------------------------------------------------------------

def test_loopback_ipv4_localhost() -> None:
    r = classify_ip("127.0.0.1")
    assert r["scope"] == "loopback"
    assert r["is_internal"] is True
    assert r["version"] == 4
    assert r["matched_cidr"] == "127.0.0.0/8"


def test_loopback_ipv4_other() -> None:
    r = classify_ip("127.100.0.1")
    assert r["scope"] == "loopback"


def test_loopback_ipv6() -> None:
    r = classify_ip("::1")
    assert r["scope"] == "loopback"
    assert r["version"] == 6
    assert r["matched_cidr"] == "::1/128"


# ---- Link-local -----------------------------------------------------------------

def test_link_local_ipv4() -> None:
    r = classify_ip("169.254.0.1")
    assert r["scope"] == "link_local"
    assert r["is_internal"] is True
    assert r["matched_cidr"] == "169.254.0.0/16"


def test_link_local_ipv4_apipa() -> None:
    r = classify_ip("169.254.169.254")
    assert r["scope"] == "link_local"


def test_link_local_ipv6() -> None:
    r = classify_ip("fe80::1")
    assert r["scope"] == "link_local"
    assert r["version"] == 6
    assert r["matched_cidr"] == "fe80::/10"
    assert r["is_internal"] is True


# ---- CGNAT ----------------------------------------------------------------------

def test_cgnat_start() -> None:
    r = classify_ip("100.64.0.1")
    assert r["scope"] == "cgnat"
    assert r["matched_cidr"] == "100.64.0.0/10"
    assert r["is_internal"] is True
    assert r["is_public"] is False


def test_cgnat_mid_range() -> None:
    r = classify_ip("100.100.50.25")
    assert r["scope"] == "cgnat"


def test_cgnat_boundary_before() -> None:
    r = classify_ip("100.63.255.255")
    assert r["scope"] != "cgnat"


# ---- Documentation / test ranges ------------------------------------------------

def test_documentation_192_0_2() -> None:
    r = classify_ip("192.0.2.1")
    assert r["scope"] == "documentation"
    assert r["matched_cidr"] == "192.0.2.0/24"
    assert r["is_special"] is True
    assert r["is_public"] is False


def test_documentation_198_51_100() -> None:
    r = classify_ip("198.51.100.1")
    assert r["scope"] == "documentation"
    assert r["matched_cidr"] == "198.51.100.0/24"


def test_documentation_203_0_113() -> None:
    r = classify_ip("203.0.113.1")
    assert r["scope"] == "documentation"
    assert r["matched_cidr"] == "203.0.113.0/24"


def test_documentation_ipv6() -> None:
    r = classify_ip("2001:db8::1")
    assert r["scope"] == "documentation"
    assert r["matched_cidr"] == "2001:db8::/32"
    assert r["version"] == 6


# ---- Reserved -------------------------------------------------------------------

def test_reserved_class_e() -> None:
    r = classify_ip("240.0.0.1")
    assert r["scope"] == "reserved"
    assert r["is_special"] is True
    assert r["is_public"] is False


def test_reserved_class_e_top() -> None:
    r = classify_ip("255.255.255.254")
    assert r["scope"] == "reserved"


# ---- Multicast ------------------------------------------------------------------

def test_multicast_ipv4() -> None:
    r = classify_ip("224.0.0.1")
    assert r["scope"] == "multicast"
    assert r["is_special"] is True
    assert r["is_public"] is False
    assert r["matched_cidr"] == "224.0.0.0/4"


def test_multicast_ipv4_all_routers() -> None:
    r = classify_ip("224.0.0.2")
    assert r["scope"] == "multicast"


def test_multicast_ipv6() -> None:
    r = classify_ip("ff02::1")
    assert r["scope"] == "multicast"
    assert r["matched_cidr"] == "ff00::/8"
    assert r["version"] == 6


# ---- IPv6 unique-local (ULA) ----------------------------------------------------

def test_ipv6_ula_fd_prefix() -> None:
    r = classify_ip("fd00::1")
    assert r["scope"] == "unique_local"
    assert r["matched_cidr"] == "fc00::/7"
    assert r["is_internal"] is True
    assert r["version"] == 6


def test_ipv6_ula_fc_prefix() -> None:
    r = classify_ip("fc00::1")
    assert r["scope"] == "unique_local"


# ---- Unspecified ----------------------------------------------------------------

def test_unspecified_ipv4() -> None:
    r = classify_ip("0.0.0.0")
    assert r["scope"] == "unspecified"
    assert r["is_special"] is True


def test_unspecified_ipv6() -> None:
    r = classify_ip("::")
    assert r["scope"] == "unspecified"
    assert r["version"] == 6


# ---- Invalid input --------------------------------------------------------------

def test_invalid_empty_string() -> None:
    r = classify_ip("")
    assert r["scope"] == "invalid"
    assert r["is_internal"] is False
    assert r["is_public"] is False


def test_invalid_none() -> None:
    r = classify_ip(None)
    assert r["scope"] == "invalid"


def test_invalid_garbage_string() -> None:
    r = classify_ip("not-an-ip")
    assert r["scope"] == "invalid"


def test_invalid_partial_address() -> None:
    r = classify_ip("192.168")
    assert r["scope"] == "invalid"


def test_invalid_whitespace_only() -> None:
    r = classify_ip("   ")
    assert r["scope"] == "invalid"


# ---- parse_internal_cidrs -------------------------------------------------------

def test_parse_internal_cidrs_valid() -> None:
    nets = parse_internal_cidrs(["10.0.0.0/8", "192.168.0.0/16"])
    assert len(nets) == 2


def test_parse_internal_cidrs_strips_whitespace() -> None:
    nets = parse_internal_cidrs(["  10.0.0.0/8  "])
    assert len(nets) == 1


def test_parse_internal_cidrs_empty_entries_skipped() -> None:
    nets = parse_internal_cidrs(["", "  ", "10.0.0.0/8"])
    assert len(nets) == 1


def test_parse_internal_cidrs_invalid_entry_skipped(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        nets = parse_internal_cidrs(["not-a-cidr", "10.0.0.0/8"])
    assert len(nets) == 1
    assert any("not-a-cidr" in r.message for r in caplog.records)


def test_parse_internal_cidrs_non_strict_host_bits() -> None:
    nets = parse_internal_cidrs(["10.0.0.5/8"])
    assert len(nets) == 1


# ---- classify_flow --------------------------------------------------------------

def test_flow_internal_to_public() -> None:
    f = classify_flow("192.168.1.1", "8.8.8.8")
    flow = f["flow"]
    assert flow["locality"] == "internal_to_public"
    assert flow["internal_to_public"] is True
    assert flow["src_internal"] is True
    assert flow["dst_internal"] is False
    assert flow["external_to_internal"] is False
    assert flow["internal_to_internal"] is False
    assert f["src"]["scope"] == "private_address"
    assert f["dst"]["scope"] == "public_internet"


def test_flow_public_to_internal() -> None:
    f = classify_flow("8.8.8.8", "10.0.0.1")
    flow = f["flow"]
    assert flow["locality"] == "public_to_internal"
    assert flow["external_to_internal"] is True
    assert flow["internal_to_public"] is False


def test_flow_internal_to_internal() -> None:
    f = classify_flow("10.0.0.1", "192.168.1.1")
    flow = f["flow"]
    assert flow["locality"] == "internal_to_internal"
    assert flow["internal_to_internal"] is True
    assert flow["src_internal"] is True
    assert flow["dst_internal"] is True


def test_flow_public_to_public() -> None:
    f = classify_flow("8.8.8.8", "1.1.1.1")
    assert f["flow"]["locality"] == "public_to_public"


def test_flow_unknown_src_none() -> None:
    f = classify_flow(None, "8.8.8.8")
    assert f["flow"]["locality"] == "unknown"


def test_flow_unknown_dst_none() -> None:
    f = classify_flow("8.8.8.8", None)
    assert f["flow"]["locality"] == "unknown"


def test_flow_unknown_both_none() -> None:
    f = classify_flow(None, None)
    assert f["flow"]["locality"] == "unknown"


def test_flow_private_or_special_multicast_to_multicast() -> None:
    f = classify_flow("224.0.0.1", "224.0.0.2")
    assert f["flow"]["locality"] == "private_or_special"


def test_flow_private_or_special_doc_to_doc() -> None:
    f = classify_flow("192.0.2.1", "198.51.100.1")
    assert f["flow"]["locality"] == "private_or_special"


def test_flow_with_configured_cidrs() -> None:
    f = classify_flow("10.20.30.1", "8.8.8.8", internal_cidrs=["10.20.30.0/24"])
    flow = f["flow"]
    assert flow["locality"] == "internal_to_public"
    assert f["src"]["scope"] == "internal_network"
    assert f["src"]["match_source"] == "configured_cidr"
