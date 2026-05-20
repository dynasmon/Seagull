from __future__ import annotations

from app.features.ueba.domain.lateral_spread import LateralSpreadDetector
from app.features.ueba.domain.outbound_bytes_burst import OutboundBytesBurstDetector
from app.features.ueba.domain.proc_exec_rate import ProcExecRateDetector
from app.features.ueba.domain.rare_process_name import RareProcessNameDetector
from app.features.ueba.domain.support import DetectorExecutionResult, DetectorRuntimeConfig, UebaDetector
from app.features.ueba.domain.ssh_login_hour import SshLoginHourDetector
from app.features.ueba.domain.ssh_source_diversity import SshSourceDiversityDetector


def default_detectors() -> list[UebaDetector]:
    return [
        SshLoginHourDetector(),
        SshSourceDiversityDetector(),
        OutboundBytesBurstDetector(),
        LateralSpreadDetector(),
        ProcExecRateDetector(),
        RareProcessNameDetector(),
    ]


__all__ = [
    "DetectorExecutionResult",
    "DetectorRuntimeConfig",
    "LateralSpreadDetector",
    "OutboundBytesBurstDetector",
    "ProcExecRateDetector",
    "RareProcessNameDetector",
    "SshLoginHourDetector",
    "SshSourceDiversityDetector",
    "UebaDetector",
    "default_detectors",
]
