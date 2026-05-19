from __future__ import annotations

from app.features.ueba.domain.support import DetectorExecutionResult, DetectorRuntimeConfig, UebaDetector
from app.features.ueba.domain.ssh_login_hour import SshLoginHourDetector
from app.features.ueba.domain.ssh_source_diversity import SshSourceDiversityDetector


def default_detectors() -> list[UebaDetector]:
    return [SshLoginHourDetector(), SshSourceDiversityDetector()]


__all__ = [
    "DetectorExecutionResult",
    "DetectorRuntimeConfig",
    "SshLoginHourDetector",
    "SshSourceDiversityDetector",
    "UebaDetector",
    "default_detectors",
]
