from __future__ import annotations

from .lifecycle import schema_status

UP_TO_DATE = 0
BEHIND_HEAD = 1
UNKNOWN_REVISION = 2


def main() -> int:
    status = schema_status()
    print(f"database revision: {status.current or '(empty)'}")
    print(f"build head:        {status.head or '(none)'}")

    if not status.known:
        print("state:             unknown revision, not present in this build")
        print(
            "                   the database was migrated by a branch whose migrations "
            "are not in this checkout"
        )
        return UNKNOWN_REVISION

    if status.drifted:
        print("state:             behind head, run './seagull db upgrade'")
        return BEHIND_HEAD

    print("state:             up to date")
    return UP_TO_DATE


if __name__ == "__main__":
    raise SystemExit(main())
