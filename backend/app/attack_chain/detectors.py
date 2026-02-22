from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from app.attack_chain.config import AttackChainConfig
from app.attack_chain.types import AttackStage, StepCandidate


def _safe_str(v: Any, *, max_len: int = 256) -> str:
    s = str(v or "")
    s = s.replace("\x00", "")
    return s[:max_len]


def _extra_action(extra: Any) -> str:
    if not isinstance(extra, dict):
        return ""
    return _safe_str(extra.get("action") or "").lower()


def _extra_username(extra: Any) -> str:
    if not isinstance(extra, dict):
        return ""
    return _safe_str(extra.get("username") or "")


def _extra_target_user(extra: Any) -> str:
    if not isinstance(extra, dict):
        return ""
    return _safe_str(extra.get("target_user") or "")


def _extra_command(extra: Any) -> str:
    if not isinstance(extra, dict):
        return ""
    return _safe_str(extra.get("command") or "", max_len=768)


_RE_SUSPICIOUS_LOG_TAMPER = re.compile(
    r"\b(truncate|shred|rm|unlink|sed\s+-i|logrotate|journalctl\s+--vacuum|>\s*/var/log/)\b",
    re.IGNORECASE,
)

_RE_DISABLE_SECURITY = re.compile(
    r"\b(systemctl\s+(stop|disable)\s+(auditd|rsyslog|systemd-journald|netwatch|iptables|ufw)|setenforce\s+0)\b",
    re.IGNORECASE,
)

# Common LOLBins often used post-compromise.
_RE_LOLBINS = re.compile(
    r"\b(bash|sh|python(3)?|perl|php|ruby|node|nc|ncat|socat|curl|wget|openssl|base64)\b",
    re.IGNORECASE,
)

_RE_SHELLS = re.compile(r"\b(bash|sh|dash|zsh|ksh|fish)\b", re.IGNORECASE)
_RE_REMOTE_FETCH_EXEC = re.compile(
    r"\b(curl|wget)\b.*\b(sh|bash)\b|\b(curl|wget)\b.*\|\s*\b(sh|bash)\b",
    re.IGNORECASE,
)
_RE_SUDO_PRIV_ESC = re.compile(
    r"\b(visudo|sudoedit|pkexec|doas)\b|\b(usermod|useradd|adduser)\b.*\b(sudo|wheel)\b|\b(chmod|chown)\b.*\+s\b|\bsetcap\b|/etc/(sudoers|passwd|shadow)\b|/root/\.ssh/authorized_keys\b",
    re.IGNORECASE,
)


def _cmd_norm(cmd: str) -> str:
    s = _safe_str(cmd or "", max_len=768)
    s = s.replace("\t", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _cmd_base(cmd: str) -> str:
    s = _cmd_norm(cmd)
    if not s:
        return ""
    head = s.split(" ", 1)[0]
    head = head.rsplit("/", 1)[-1]
    return head.lower()


def _is_routine_privileged_cmd(cmd: str) -> bool:
    """Best-effort suppression for common admin maintenance.

    Attack-chain should focus on suspicious progressions, not routine operations.
    """

    s = _cmd_norm(cmd)
    if not s:
        return True

    # Anything that looks like defense evasion / tamper is never routine.
    if _RE_SUSPICIOUS_LOG_TAMPER.search(s) or _RE_DISABLE_SECURITY.search(s):
        return False

    # Explicit privilege escalation / persistence primitives are never routine.
    if _RE_SUDO_PRIV_ESC.search(s) or _RE_REMOTE_FETCH_EXEC.search(s):
        return False

    base = _cmd_base(s)
    routine = {
        "apt",
        "apt-get",
        "yum",
        "dnf",
        "pacman",
        "apk",
        "systemctl",
        "service",
        "journalctl",
        "tail",
        "less",
        "cat",
        "ls",
        "df",
        "du",
        "ip",
        "ss",
        "netstat",
        "ps",
        "top",
        "free",
        "uname",
        "whoami",
        "id",
        "uptime",
    }

    if base in routine:
        return True

    # If we cannot confidently call it routine, keep it as a low-confidence signal.
    return False


def _classify_sudo(username: str, target: str, cmd: str, cfg: AttackChainConfig) -> StepCandidate:
    """Classify a sudo command into an ATT&CK-aligned step.

    IMPORTANT: Running sudo itself is not inherently an attacker privilege escalation.
    We treat routine admin usage as context/noise unless it correlates with other signals.
    """

    cmd_n = _cmd_norm(cmd)
    base = _cmd_base(cmd_n)
    tgt = (target or "").strip().lower()

    # Defense evasion (high confidence)
    if cmd_n and (_RE_SUSPICIOUS_LOG_TAMPER.search(cmd_n) or _RE_DISABLE_SECURITY.search(cmd_n)):
        return StepCandidate(
            stage=AttackStage.defense_evasion,
            title="Defense evasion via privileged command",
            description="Command indicates log tampering or disabling security controls.",
            score_delta=int(getattr(cfg, "sudo_defense_evasion_score", 30)),
            fingerprint=f"sudo:def_evasion:{username}:{cmd_n}",
            suspect_ip=None,
            details={"username": username, "target_user": target, "command": cmd_n, "reason": "tamper_or_disable"},
            kind="sudo_defense_evasion",
            technique_id="T1562",
            confidence=85,
            emit=True,
        )

    # Strong privilege escalation / persistence primitives (medium-high)
    if cmd_n and _RE_SUDO_PRIV_ESC.search(cmd_n):
        # Map a few common patterns.
        tid = "T1548.003"  # Sudo and Sudo Caching
        stage = AttackStage.privilege_escalation
        if "/root/.ssh/authorized_keys" in cmd_n.lower() or "authorized_keys" in cmd_n.lower():
            stage = AttackStage.persistence
            tid = "T1098"  # Account Manipulation / SSH authorized_keys
        return StepCandidate(
            stage=stage,
            title="High-risk privileged command",
            description="Command matches privilege escalation or persistence primitives.",
            score_delta=int(getattr(cfg, "sudo_priv_escalation_score", 24)),
            fingerprint=f"sudo:privesc:{username}:{cmd_n}",
            suspect_ip=None,
            details={"username": username, "target_user": target, "command": cmd_n, "reason": "privesc_or_persist"},
            kind="sudo_priv_escalation",
            technique_id=tid,
            confidence=75,
            emit=True,
        )

    # Remote fetch + execute (execution) (high)
    if cmd_n and _RE_REMOTE_FETCH_EXEC.search(cmd_n):
        return StepCandidate(
            stage=AttackStage.execution,
            title="Remote fetch and execute (privileged)",
            description="Command downloads content and pipes it to a shell.",
            score_delta=int(getattr(cfg, "sudo_remote_exec_score", 26)),
            fingerprint=f"sudo:remote_exec:{username}:{cmd_n}",
            suspect_ip=None,
            details={"username": username, "target_user": target, "command": cmd_n, "reason": "download_pipe_shell"},
            kind="sudo_remote_exec",
            technique_id="T1059",
            confidence=85,
            emit=True,
        )

    # Shell spawn or LOLBin under sudo (execution) (medium)
    if base and (_RE_SHELLS.search(base) or base in {"su", "python", "python3", "perl", "php", "ruby", "node", "nc", "ncat", "socat", "openssl", "base64"}):
        return StepCandidate(
            stage=AttackStage.execution,
            title="Interactive shell / LOLBin via sudo",
            description="Privileged command looks like an interactive shell or a common LOLBin.",
            score_delta=int(getattr(cfg, "sudo_lolbin_score", 14)),
            fingerprint=f"sudo:lolbin:{username}:{cmd_n}",
            suspect_ip=None,
            details={"username": username, "target_user": target, "command": cmd_n, "reason": "lolbin_or_shell"},
            kind="sudo_lolbin",
            technique_id="T1059",
            confidence=65,
            emit=True,
        )

    # Routine admin usage: do not emit by default.
    if _is_routine_privileged_cmd(cmd_n):
        return StepCandidate(
            stage=AttackStage.execution,
            title="Routine privileged command",
            description="Likely normal maintenance. Suppressed unless correlated with other signals.",
            score_delta=0,
            fingerprint=f"sudo:routine:{username}:{cmd_n}",
            suspect_ip=None,
            details={"username": username, "target_user": target, "command": cmd_n, "reason": "routine"},
            kind="sudo_routine",
            technique_id="T1548.003" if tgt in {"root", "administrator"} else None,
            confidence=20,
            emit=False,
        )

    # Fallback: privileged execution (low confidence)
    return StepCandidate(
        stage=AttackStage.execution,
        title="Privileged command executed",
        description="Privileged execution observed. Review command context for intent.",
        score_delta=int(getattr(cfg, "sudo_exec_score", 6)),
        fingerprint=f"sudo:exec:{username}:{cmd_n}",
        suspect_ip=None,
        details={"username": username, "target_user": target, "command": cmd_n, "reason": "privileged_exec"},
        kind="sudo_exec",
        technique_id="T1548.003" if tgt in {"root", "administrator"} else None,
        confidence=35,
        emit=True,
    )


def detect_steps(event: Dict[str, Any], cfg: AttackChainConfig) -> List[StepCandidate]:
    """Translate a raw net_event row into high-level attack-chain steps."""

    out: List[StepCandidate] = []

    et = _safe_str(event.get("event_type") or "")
    src_ip = _safe_str(event.get("src_ip") or "")
    extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}

    # --- Initial Access (SSH)
    if et == "ssh_auth":
        action = _extra_action(extra)
        user = _extra_username(extra)

        # NOTE: SSH failures/accepts are used heavily for correlation.
        # We emit them as non-visible candidates by default; the worker decides
        # when they become a real case step (e.g., brute-force threshold reached
        # or success after failures / new source).
        if action in {"failed_password", "invalid_user"}:
            out.append(
                StepCandidate(
                    stage=AttackStage.initial_access,
                    title="SSH authentication failure",
                    description="Failed SSH authentication attempt.",
                    score_delta=0,
                    fingerprint=f"ssh_fail:{src_ip}:{user}:{action}",
                    suspect_ip=src_ip or None,
                    details={"action": action, "username": user, "src_ip": src_ip},
                    kind="ssh_fail",
                    technique_id="T1110.001",
                    confidence=60,
                    emit=False,
                )
            )

        if action == "accepted":
            out.append(
                StepCandidate(
                    stage=AttackStage.initial_access,
                    title="SSH login accepted",
                    description="Successful SSH authentication.",
                    score_delta=0,
                    fingerprint=f"ssh_ok:{src_ip}:{user}",
                    suspect_ip=src_ip or None,
                    details={"action": action, "username": user, "src_ip": src_ip},
                    kind="ssh_accept",
                    technique_id="T1078",
                    confidence=40,
                    emit=False,
                )
            )

    # --- Privilege escalation / Execution / Defense evasion (sudo)
    if et == "sudo_cmd":
        username = _extra_username(extra)
        target = _extra_target_user(extra)
        cmd = _extra_command(extra)
        out.append(_classify_sudo(username, target, cmd, cfg))

    # --- Future-proof hooks (eBPF + FIM + C2/Exfil)
    # These are intentionally conservative so the backend is ready for the next agents.
    if et in {"ebpf_exec", "proc_exec"}:
        argv = _safe_str(extra.get("argv") or extra.get("cmdline") or "", max_len=1024)
        bin_name = _safe_str(extra.get("binary") or extra.get("comm") or "")
        if argv and _RE_LOLBINS.search(argv):
            out.append(
                StepCandidate(
                    stage=AttackStage.execution,
                    title="LOLBin execution",
                    description="Execution of a common LOLBin observed.",
                    score_delta=12,
                    fingerprint=f"exec_lolbin:{bin_name}:{argv}",
                    suspect_ip=src_ip or None,
                    details={"binary": bin_name, "argv": argv},
                    kind="exec_lolbin",
                    technique_id="T1059",
                    confidence=65,
                )
            )

    if et in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        path = _safe_str(extra.get("path") or "")
        out.append(
            StepCandidate(
                stage=AttackStage.persistence,
                    title="Persistence indicator",
                    description="Potential persistence-related change observed.",
                score_delta=26,
                fingerprint=f"persist:{et}:{path}",
                suspect_ip=None,
                details={"event_type": et, "path": path, "op": _safe_str(extra.get("op") or "")},
                    kind="persistence",
                    technique_id="T1543",
                    confidence=70,
            )
        )

    if et in {"beacon_suspect", "c2_suspect"}:
        out.append(
            StepCandidate(
                stage=AttackStage.command_and_control,
                title="Command & Control indicator",
                description="Suspicious outbound pattern consistent with beaconing/control traffic.",
                score_delta=28,
                fingerprint=f"c2:{src_ip}:{_safe_str(event.get('dst_ip') or '')}:{_safe_str(event.get('dst_port') or '')}",
                suspect_ip=src_ip or None,
                details={"src_ip": src_ip, "dst_ip": _safe_str(event.get("dst_ip") or ""), "dst_port": event.get("dst_port")},
                kind="c2",
                technique_id="T1071",
                confidence=75,
            )
        )

    if et in {"exfil_suspect", "egress_anomaly"}:
        out.append(
            StepCandidate(
                stage=AttackStage.exfiltration,
                title="Potential exfiltration",
                description="Anomalous egress activity consistent with data exfiltration.",
                score_delta=34,
                fingerprint=f"exfil:{src_ip}:{_safe_str(event.get('dst_ip') or '')}:{_safe_str(event.get('dst_port') or '')}",
                suspect_ip=src_ip or None,
                details={"src_ip": src_ip, "dst_ip": _safe_str(event.get("dst_ip") or ""), "bytes": event.get("bytes")},
                kind="exfil",
                technique_id="T1041",
                confidence=75,
            )
        )

    return out
