from __future__ import annotations

import re
import shutil
from datetime import date
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parent.parent.parent

_DEPRECATED_KEYS = ["COMPOSE_IGNORE_ORPHANS"]


def root() -> Path:
    return ROOT


def env_path(name: str = ".env") -> Path:
    return ROOT / name


def read(key: str, default: str = "", path: Optional[Path] = None) -> str:
    p = path or env_path()
    if not p.exists():
        return default
    for line in p.read_text().splitlines():
        if line.startswith(f"{key}="):
            return line[len(key) + 1:].strip()
    return default


def upsert(key: str, value: str, path: Optional[Path] = None) -> None:
    p = path or env_path()
    lines = p.read_text().splitlines() if p.exists() else []
    out: list[str] = []
    found = False
    for line in lines:
        if line.startswith(f"{key}="):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(line)
    if not found:
        if out and out[-1].strip():
            out.append("")
        out.append(f"{key}={value}")
    p.write_text("\n".join(out) + "\n")


def bootstrap(env_file: Optional[Path] = None, template: Optional[Path] = None) -> None:
    path = env_file or env_path()
    tmpl = template or env_path(".env.example")

    if not tmpl.exists():
        raise FileNotFoundError(f"template not found: {tmpl}")

    if not path.exists():
        shutil.copy(tmpl, path)
        print(f"[bootstrap] created {path.name} from {tmpl.name}")
        return

    text = path.read_text()
    removed = 0
    for key in _DEPRECATED_KEYS:
        new_text = re.sub(
            rf"^\s*{re.escape(key)}=.*\n?", "", text, flags=re.MULTILINE
        )
        if new_text != text:
            text = new_text
            removed += 1
    if removed:
        path.write_text(text)

    existing: set[str] = set()
    for line in path.read_text().splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m:
            existing.add(m.group(1))

    added: list[str] = []
    for line in tmpl.read_text().splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m and m.group(1) not in existing:
            added.append(line)
            existing.add(m.group(1))

    if added:
        header = f"\n# --- Auto-added from {tmpl.name} on {date.today().isoformat()} ---"
        with path.open("a") as f:
            f.write(header + "\n")
            for line in added:
                f.write(line + "\n")
        print(f"[bootstrap] synced {len(added)} missing vars from {tmpl.name} into {path.name}")
    else:
        print(f"[bootstrap] {path.name} already up-to-date")

    if removed:
        print(f"[bootstrap] removed {removed} deprecated var(s) from {path.name}")
