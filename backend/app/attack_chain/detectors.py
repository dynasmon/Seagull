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

        if action in {"failed_password", "invalid_user"}:
            out.append(
                StepCandidate(
                    stage=AttackStage.initial_access,
                    label="SSH authentication failures",
                    score_delta=int(cfg.ssh_bruteforce_step_score),
                    fingerprint=f"ssh_fail:{src_ip}:{user}:{action}",
                    suspect_ip=src_ip or None,
                    details={"action": action, "username": user, "src_ip": src_ip},
                )
            )

        if action == "accepted":
            out.append(
                StepCandidate(
                    stage=AttackStage.initial_access,
                    label="SSH login accepted",
                    score_delta=int(cfg.ssh_success_score),
                    fingerprint=f"ssh_ok:{src_ip}:{user}",
                    suspect_ip=src_ip or None,
                    details={"action": action, "username": user, "src_ip": src_ip},
                )
            )

    # --- Privilege escalation / Execution / Defense evasion (sudo)
    if et == "sudo_cmd":
        username = _extra_username(extra)
        target = _extra_target_user(extra)
        cmd = _extra_command(extra)

        # PrivEsc: sudo to root (or other privileged accounts)
        if (target or "").lower() in {"root", "administrator"}:
            out.append(
                StepCandidate(
                    stage=AttackStage.privilege_escalation,
                    label="Sudo escalation to privileged user",
                    score_delta=int(cfg.sudo_root_score),
                    fingerprint=f"sudo_root:{username}:{cmd}",
                    suspect_ip=None,
                    details={"username": username, "target_user": target, "command": cmd},
                )
            )

        # Execution: LOLBins used under sudo.
        if cmd and _RE_LOLBINS.search(cmd):
            out.append(
                StepCandidate(
                    stage=AttackStage.execution,
                    label="Suspicious LOLBin executed via sudo",
                    score_delta=int(cfg.sudo_lolbin_score),
                    fingerprint=f"sudo_lolbin:{username}:{cmd}",
                    suspect_ip=None,
                    details={"username": username, "command": cmd, "hint": "lolbin"},
                )
            )

        # Defense evasion: log tampering / disabling security services.
        if cmd and (_RE_SUSPICIOUS_LOG_TAMPER.search(cmd) or _RE_DISABLE_SECURITY.search(cmd)):
            out.append(
                StepCandidate(
                    stage=AttackStage.defense_evasion,
                    label="Potential log tampering / defense evasion",
                    score_delta=int(cfg.log_tamper_score),
                    fingerprint=f"def_evasion:{username}:{cmd}",
                    suspect_ip=None,
                    details={"username": username, "command": cmd, "hint": "tamper_or_disable"},
                )
            )

    # --- Future-proof hooks (eBPF + FIM + C2/Exfil)
    # These are intentionally conservative so the backend is ready for the next agents.
    if et in {"ebpf_exec", "proc_exec"}:
        argv = _safe_str(extra.get("argv") or extra.get("cmdline") or "", max_len=1024)
        bin_name = _safe_str(extra.get("binary") or extra.get("comm") or "")
        if argv and _RE_LOLBINS.search(argv):
            out.append(
                StepCandidate(
                    stage=AttackStage.execution,
                    label="LOLBin execution",
                    score_delta=12,
                    fingerprint=f"exec_lolbin:{bin_name}:{argv}",
                    suspect_ip=src_ip or None,
                    details={"binary": bin_name, "argv": argv},
                )
            )

    if et in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        path = _safe_str(extra.get("path") or "")
        out.append(
            StepCandidate(
                stage=AttackStage.persistence,
                label="Persistence indicator",
                score_delta=26,
                fingerprint=f"persist:{et}:{path}",
                suspect_ip=None,
                details={"event_type": et, "path": path, "op": _safe_str(extra.get("op") or "")},
            )
        )

    if et in {"beacon_suspect", "c2_suspect"}:
        out.append(
            StepCandidate(
                stage=AttackStage.command_and_control,
                label="Command & Control indicator",
                score_delta=28,
                fingerprint=f"c2:{src_ip}:{_safe_str(event.get('dst_ip') or '')}:{_safe_str(event.get('dst_port') or '')}",
                suspect_ip=src_ip or None,
                details={"src_ip": src_ip, "dst_ip": _safe_str(event.get("dst_ip") or ""), "dst_port": event.get("dst_port")},
            )
        )

    if et in {"exfil_suspect", "egress_anomaly"}:
        out.append(
            StepCandidate(
                stage=AttackStage.exfiltration,
                label="Potential exfiltration",
                score_delta=34,
                fingerprint=f"exfil:{src_ip}:{_safe_str(event.get('dst_ip') or '')}:{_safe_str(event.get('dst_port') or '')}",
                suspect_ip=src_ip or None,
                details={"src_ip": src_ip, "dst_ip": _safe_str(event.get("dst_ip") or ""), "bytes": event.get("bytes")},
            )
        )

    return out
