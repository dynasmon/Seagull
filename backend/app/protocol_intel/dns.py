from __future__ import annotations

from math import log2
from typing import Any, Dict, List, Optional, Tuple


def _read_u16(b: bytes, i: int) -> Tuple[int, int]:
    return (b[i] << 8 | b[i + 1]), i + 2


def _read_u32(b: bytes, i: int) -> Tuple[int, int]:
    return (b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]), i + 4


def _is_pointer(label_len: int) -> bool:
    return (label_len & 0xC0) == 0xC0


def _decode_name(b: bytes, i: int, depth: int = 0) -> Tuple[str, int]:
    """Decode a DNS name with compression support.

    Safety:
    - depth-limited recursion
    - bounds checks
    """

    if depth > 8:
        return "", i

    labels: List[str] = []
    start = i

    while i < len(b):
        l = b[i]
        if l == 0:
            i += 1
            break

        if _is_pointer(l):
            if i + 1 >= len(b):
                return "", i + 1
            ptr = ((l & 0x3F) << 8) | b[i + 1]
            name, _ = _decode_name(b, ptr, depth + 1)
            if name:
                labels.append(name)
            i += 2
            break

        i += 1
        if i + l > len(b):
            return "", i
        try:
            labels.append(b[i : i + l].decode("ascii", "ignore"))
        except Exception:
            labels.append("")
        i += l

    # If we consumed a pointer, i already advanced. For question section, the caller
    # needs to advance using the original bytes. We return i (current offset).
    name = ".".join([x for x in labels if x])
    # Normalize trailing dot.
    name = name.strip(".")
    return name, i


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * log2(p)
    return ent


def _risk_score(qname: str) -> int:
    """Very lightweight DNS risk score (0..100).

    It's intentionally heuristic and explainable: high entropy and long labels
    are a common signal for DGAs / tracking domains.
    """

    if not qname:
        return 0

    parts = [p for p in qname.split(".") if p]
    if not parts:
        return 0

    longest = max(len(p) for p in parts)
    ent = _entropy(qname)
    tld = parts[-1].lower()

    score = 0
    if len(qname) >= 45:
        score += 20
    if longest >= 20:
        score += 20
    if ent >= 4.0:
        score += 20

    if tld in {"zip", "mov", "top", "xyz", "gq", "tk", "cn"}:
        score += 15

    if qname.count("-") >= 4:
        score += 10

    return min(score, 100)


def parse_dns_message(payload: bytes) -> Dict[str, Any]:
    """Parse a DNS message (UDP/TCP payload).

    Returns a dict with keys prefixed by dns_*.

    If parsing fails, returns an empty dict.
    """

    out: Dict[str, Any] = {}
    b = payload
    if len(b) < 12:
        return out

    try:
        _id, i = _read_u16(b, 0)
        flags, i = _read_u16(b, i)
        qd, i = _read_u16(b, i)
        an, i = _read_u16(b, i)
        ns, i = _read_u16(b, i)
        ar, i = _read_u16(b, i)

        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1
        ra = (flags >> 7) & 1
        rcode = flags & 0xF

        out["dns_is_response"] = bool(qr)
        out["dns_opcode"] = int(opcode)
        out["dns_rcode"] = int(rcode)
        out["dns_flags"] = {"aa": bool(aa), "tc": bool(tc), "rd": bool(rd), "ra": bool(ra)}
        out["dns_counts"] = {"qd": int(qd), "an": int(an), "ns": int(ns), "ar": int(ar)}

        # Questions (we usually care about the first one).
        qname = ""
        qtype = None
        if qd > 0:
            qname, i = _decode_name(b, i)
            if i + 4 <= len(b):
                qtype, i = _read_u16(b, i)
                _qclass, i = _read_u16(b, i)

        if qname:
            out["dns_qname"] = qname
            out["dns_risk"] = _risk_score(qname)
        if qtype is not None:
            out["dns_qtype"] = int(qtype)

        # Answers (best-effort; capped).
        answers: List[str] = []
        max_rr = min(an, 8)
        for _ in range(max_rr):
            name, i = _decode_name(b, i)
            if i + 10 > len(b):
                break
            rtype, i = _read_u16(b, i)
            _rclass, i = _read_u16(b, i)
            _ttl, i = _read_u32(b, i)
            rdlen, i = _read_u16(b, i)
            if i + rdlen > len(b):
                break
            rdata = b[i : i + rdlen]
            i += rdlen

            # A/AAAA/CNAME
            if rtype == 1 and rdlen == 4:
                answers.append(".".join(str(x) for x in rdata))
            elif rtype == 28 and rdlen == 16:
                parts = [rdata[j : j + 2].hex() for j in range(0, 16, 2)]
                # Simple zero compression is not needed for analysis.
                answers.append(":".join(parts))
            elif rtype == 5:
                cname, _ = _decode_name(b, i - rdlen, 0)
                if cname:
                    answers.append(cname)

        if answers:
            out["dns_answers"] = answers

        return out
    except Exception:
        return {}
