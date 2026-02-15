"""IP intelligence worker entrypoint.

This is a compatibility shim.

Some deployments reference this module as the worker command:

  python -m app.workers.ip_intel

The original implementation currently lives in `lupe_enricher.py`.
Until the project fully standardizes naming, we keep this thin wrapper
so Docker Compose/Swarm stacks don't break.
"""

from .lupe_enricher import main


if __name__ == "__main__":
    main()
