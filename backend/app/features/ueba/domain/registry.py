from __future__ import annotations

from app.features.ueba.domain.fim_spike import FimSpikeDetector
from app.features.ueba.domain.lateral_spread import LateralSpreadDetector
from app.features.ueba.domain.outbound_bytes_burst import OutboundBytesBurstDetector
from app.features.ueba.domain.peer_group_deviation import PeerGroupDeviationDetector
from app.features.ueba.domain.proc_exec_rate import ProcExecRateDetector
from app.features.ueba.domain.rare_process_name import RareProcessNameDetector
from app.features.ueba.domain.ssh_login_hour import SshLoginHourDetector
from app.features.ueba.domain.ssh_source_diversity import SshSourceDiversityDetector
from app.features.ueba.domain.sudo_session_hour import SudoSessionHourDetector
from app.features.ueba.domain.support import DetectorExecutionResult, DetectorRuntimeConfig, UebaDetector


def default_detectors() -> list[UebaDetector]:
    return [
        SshLoginHourDetector(),
        SshSourceDiversityDetector(),
        OutboundBytesBurstDetector(),
        LateralSpreadDetector(),
        ProcExecRateDetector(),
        RareProcessNameDetector(),
        FimSpikeDetector(),
        SudoSessionHourDetector(),
        PeerGroupDeviationDetector(),
    ]


__all__ = [
    "DetectorExecutionResult",
    "DetectorRuntimeConfig",
    "FimSpikeDetector",
    "LateralSpreadDetector",
    "OutboundBytesBurstDetector",
    "PeerGroupDeviationDetector",
    "ProcExecRateDetector",
    "RareProcessNameDetector",
    "SshLoginHourDetector",
    "SshSourceDiversityDetector",
    "SudoSessionHourDetector",
    "UebaDetector",
    "default_detectors",
]
