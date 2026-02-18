"""Attack Chain detection & scoring.

This subsystem converts low-level telemetry into stateful "cases" representing
attack progression across MITRE-like stages.

Design goals:
- Low noise: emit operator-friendly steps instead of mirroring raw event spam.
- Durable state: cases survive worker restarts.
- Extensible: adding new detectors should not require touching storage/API code.
"""
