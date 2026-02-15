from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple


def _is_grease_u16(v: int) -> bool:
    # GREASE values: 0x0a0a, 0x1a1a, ..., 0xfafa
    return (v & 0x0F0F) == 0x0A0A and ((v >> 8) & 0xF0) == (v & 0xF0)


def _u16_hex(v: int) -> str:
    return f"{v:04x}"


def _sha256_12(s: str) -> str:
    h = hashlib.sha256(s.encode("ascii", "ignore")).hexdigest().lower()
    return h[:12]


def _tls_version_code(v: int) -> str:
    # Spec mapping from FoxIO JA4.
    return {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0002: "s2",
        0xFEFF: "d1",
        0xFEFD: "d2",
        0xFEFC: "d3",
    }.get(v, "00")


def _alpn_tag(first_proto: bytes) -> str:
    if not first_proto:
        return "00"

    # First and last ASCII alphanumeric characters.
    a = first_proto[0]
    z = first_proto[-1]
    is_alnum = lambda c: (0x30 <= c <= 0x39) or (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A)

    if is_alnum(a) and is_alnum(z):
        try:
            return bytes([a]).decode("ascii").lower() + bytes([z]).decode("ascii").lower()
        except Exception:
            pass

    hx = first_proto.hex().lower()
    if len(hx) == 1:
        return hx + hx
    if len(hx) == 2:
        return hx
    return hx[0] + hx[-1]


def _read_u8(b: bytes, i: int) -> Tuple[int, int]:
    return b[i], i + 1


def _read_u16(b: bytes, i: int) -> Tuple[int, int]:
    return (b[i] << 8 | b[i + 1]), i + 2


def _read_u24(b: bytes, i: int) -> Tuple[int, int]:
    return (b[i] << 16 | b[i + 1] << 8 | b[i + 2]), i + 3


def _slice(b: bytes, i: int, n: int) -> Tuple[bytes, int]:
    return b[i : i + n], i + n


def _parse_sni(ext: bytes) -> Optional[str]:
    # SNI extension structure.
    # uint16 list_len
    # repeated: uint8 name_type, uint16 name_len, opaque name
    try:
        if len(ext) < 2:
            return None
        list_len = int.from_bytes(ext[0:2], "big")
        i = 2
        end = min(len(ext), 2 + list_len)
        while i + 3 <= end:
            name_type = ext[i]
            name_len = int.from_bytes(ext[i + 1 : i + 3], "big")
            i += 3
            if i + name_len > end:
                break
            if name_type == 0:
                host = ext[i : i + name_len].decode("idna", "ignore")
                return host.strip(".") or None
            i += name_len
        return None
    except Exception:
        return None


def _parse_alpn(ext: bytes) -> List[bytes]:
    # ALPN: uint16 list_len, then repeated: uint8 len, opaque value
    out: List[bytes] = []
    try:
        if len(ext) < 2:
            return out
        list_len = int.from_bytes(ext[0:2], "big")
        i = 2
        end = min(len(ext), 2 + list_len)
        while i < end:
            ln = ext[i]
            i += 1
            if ln <= 0 or i + ln > end:
                break
            out.append(ext[i : i + ln])
            i += ln
        return out
    except Exception:
        return out


def _parse_supported_groups(ext: bytes) -> List[int]:
    out: List[int] = []
    if len(ext) < 2:
        return out
    ln = int.from_bytes(ext[0:2], "big")
    i = 2
    end = min(len(ext), 2 + ln)
    while i + 2 <= end:
        v = int.from_bytes(ext[i : i + 2], "big")
        i += 2
        if _is_grease_u16(v):
            continue
        out.append(v)
    return out


def _parse_ec_point_formats(ext: bytes) -> List[int]:
    out: List[int] = []
    if not ext:
        return out
    ln = ext[0]
    i = 1
    end = min(len(ext), 1 + ln)
    while i < end:
        out.append(ext[i])
        i += 1
    return out


def _parse_signature_algorithms(ext: bytes) -> List[int]:
    out: List[int] = []
    if len(ext) < 2:
        return out
    ln = int.from_bytes(ext[0:2], "big")
    i = 2
    end = min(len(ext), 2 + ln)
    while i + 2 <= end:
        v = int.from_bytes(ext[i : i + 2], "big")
        i += 2
        if _is_grease_u16(v):
            continue
        out.append(v)
    return out


def _infer_ptype(extra: Dict[str, Any], is_dtls: bool, is_quic: bool) -> str:
    # Agent evidence wins.
    v = str(extra.get("ja4_ptype") or "").strip().lower()
    if v in ("q", "d", "t"):
        return v
    if bool(extra.get("is_quic")):
        return "q"
    if bool(extra.get("is_dtls")):
        return "d"

    # Transport hint.
    tr = str(extra.get("transport") or "").strip().lower()
    if tr.startswith("udp") and is_quic:
        return "q"
    if is_dtls:
        return "d"
    return "t"


def parse_tls_client_hello(payload: bytes, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Parse TLS/DTLS ClientHello and derive JA3/JA4.

    The input should be the beginning of a TLS/DTLS record that contains a ClientHello.
    QUIC ClientHello requires the agent to extract the embedded TLS ClientHello bytes;
    when that happens, this function will still compute JA4 and set ptype='q' if the
    agent provides the proper hints.
    """

    out: Dict[str, Any] = {}
    extra = extra or {}

    b = payload
    if len(b) < 5:
        return out

    # Detect DTLS record header.
    # DTLS record: content_type(1), version(2), epoch(2), seq(6), length(2)
    is_dtls = False
    content_type = b[0]
    if content_type == 22 and len(b) >= 13:
        ver = int.from_bytes(b[1:3], "big")
        if ver in (0xFEFF, 0xFEFD, 0xFEFC):
            is_dtls = True

    # Detect QUIC (agent hint only).
    is_quic = bool(extra.get("is_quic"))

    try:
        if is_dtls:
            if len(b) < 13:
                return out
            legacy_record_version = int.from_bytes(b[1:3], "big")
            record_len = int.from_bytes(b[11:13], "big")
            rec = b[13 : 13 + record_len]
        else:
            legacy_record_version = int.from_bytes(b[1:3], "big")
            record_len = int.from_bytes(b[3:5], "big")
            rec = b[5 : 5 + record_len]

        if not rec or len(rec) < 4:
            return out

        # Handshake: type(1)=1 for ClientHello, length(3)
        hs_type = rec[0]
        if hs_type != 1:
            return out
        hs_len = int.from_bytes(rec[1:4], "big")
        body = rec[4 : 4 + hs_len]
        if len(body) < 42:
            return out

        i = 0
        # legacy_version in ClientHello.
        client_hello_version = int.from_bytes(body[i : i + 2], "big")
        i += 2
        # random
        i += 32
        # session_id
        sid_len = body[i]
        i += 1 + sid_len
        # cipher_suites
        cs_len = int.from_bytes(body[i : i + 2], "big")
        i += 2
        ciphers: List[int] = []
        for j in range(0, min(cs_len, len(body) - i), 2):
            v = int.from_bytes(body[i + j : i + j + 2], "big")
            if _is_grease_u16(v):
                continue
            ciphers.append(v)
        i += cs_len
        # compression methods
        if i >= len(body):
            return out
        comp_len = body[i]
        i += 1 + comp_len
        if i > len(body):
            return out
        # extensions
        exts: List[int] = []
        sni = None
        alpns: List[bytes] = []
        supported_groups: List[int] = []
        ec_point_formats: List[int] = []
        sig_algs: List[int] = []
        supported_versions: List[int] = []

        if i + 2 <= len(body):
            ext_len = int.from_bytes(body[i : i + 2], "big")
            i += 2
            end = min(len(body), i + ext_len)
            while i + 4 <= end:
                etype = int.from_bytes(body[i : i + 2], "big")
                elen = int.from_bytes(body[i + 2 : i + 4], "big")
                i += 4
                if i + elen > end:
                    break
                ev = body[i : i + elen]
                i += elen

                if _is_grease_u16(etype):
                    continue

                exts.append(etype)

                if etype == 0x0000:
                    sni = _parse_sni(ev) or sni
                elif etype == 0x0010:
                    alpns = _parse_alpn(ev) or alpns
                elif etype == 0x000A:
                    supported_groups = _parse_supported_groups(ev) or supported_groups
                elif etype == 0x000B:
                    ec_point_formats = _parse_ec_point_formats(ev) or ec_point_formats
                elif etype == 0x000D:
                    sig_algs = _parse_signature_algorithms(ev) or sig_algs
                elif etype == 0x002B:
                    # supported_versions
                    if len(ev) >= 3:
                        ln = ev[0]
                        j = 1
                        end2 = min(len(ev), 1 + ln)
                        while j + 2 <= end2:
                            vv = int.from_bytes(ev[j : j + 2], "big")
                            j += 2
                            if _is_grease_u16(vv):
                                continue
                            supported_versions.append(vv)

        # JA3 (classic): version,ciphers,extensions,elliptic_curves,ec_point_formats
        ja3_version = client_hello_version
        ja3_ciphers = "-".join(str(v) for v in ciphers)
        ja3_exts = "-".join(str(v) for v in exts)
        ja3_groups = "-".join(str(v) for v in supported_groups)
        ja3_ecpf = "-".join(str(v) for v in ec_point_formats)
        ja3_raw = f"{ja3_version},{ja3_ciphers},{ja3_exts},{ja3_groups},{ja3_ecpf}"
        ja3 = hashlib.md5(ja3_raw.encode("ascii", "ignore")).hexdigest()

        out["ja3"] = ja3
        out["ja3_raw"] = ja3_raw

        # JA4 per FoxIO spec.
        # Version: highest in supported_versions; else client_hello_version (protocol version field)
        ver_pick = None
        if supported_versions:
            ver_pick = max(supported_versions)
        else:
            ver_pick = client_hello_version

        ver_code = _tls_version_code(ver_pick)
        sni_flag = "d" if (0x0000 in exts) else "i"

        cipher_count = len(ciphers)
        ext_count = len(exts)
        cipher_count_s = f"{min(cipher_count, 99):02d}"
        ext_count_s = f"{min(ext_count, 99):02d}"

        first_alpn = alpns[0] if alpns else b""
        alpn_code = _alpn_tag(first_alpn)

        ptype = _infer_ptype(extra, is_dtls=is_dtls, is_quic=is_quic)

        ja4_a = f"{ptype}{ver_code}{sni_flag}{cipher_count_s}{ext_count_s}{alpn_code}"

        # JA4_b: sha256 of sorted cipher hex codes.
        cipher_hexes = sorted(_u16_hex(v) for v in ciphers)
        if cipher_hexes:
            ja4_b = _sha256_12(",".join(cipher_hexes))
        else:
            ja4_b = "000000000000"

        # JA4_c: sha256 of (sorted extensions minus SNI/ALPN) + '_' + sigalgs in-order
        exts_filtered = [v for v in exts if v not in (0x0000, 0x0010)]
        exts_hexes = sorted(_u16_hex(v) for v in exts_filtered)
        if exts_hexes:
            base = ",".join(exts_hexes)
            if sig_algs:
                base = base + "_" + ",".join(_u16_hex(v) for v in sig_algs)
            ja4_c = _sha256_12(base)
        else:
            ja4_c = "000000000000"

        ja4 = f"{ja4_a}_{ja4_b}_{ja4_c}"

        out["ja4"] = ja4
        out["ja4_a"] = ja4_a
        out["ja4_b"] = ja4_b
        out["ja4_c"] = ja4_c
        out["ja4_ptype"] = ptype

        # Extra TLS metadata for UI/hunting.
        if sni:
            out["tls_sni"] = sni
        if alpns:
            try:
                out["tls_alpn_first"] = alpns[0].decode("ascii", "ignore")
            except Exception:
                out["tls_alpn_first"] = alpns[0].hex()
        out["tls_version"] = ver_code

        return out

    except Exception:
        return {}


# Backward/typo-friendly aliases (do not remove)
parse_tls_clienthello = parse_tls_client_hello  # type: ignore
parse_client_hello = parse_tls_client_hello  # type: ignore
