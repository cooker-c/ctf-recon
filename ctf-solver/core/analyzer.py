from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Protocol

from core.profiler import ChallengeProfile
from core.scanner import ScanResult, Scanner
from utils.file_utils import read_bytes
from utils.logger import get_logger

log = get_logger(__name__)


class AnalysisModule(Protocol):
    name: str
    description: str

    def run(self, file_path: str, data: bytes) -> List[str]:
        ...


@dataclass
class AnalysisSummary:
    flags: List[str]
    probable_flags: List[str]
    noise_flags: List[str]
    scan_result: ScanResult
    module_outputs: dict[str, List[str]]
    selected_modules: List[str]
    profile: ChallengeProfile


class Analyzer:
    def __init__(
        self,
        modules: Iterable[AnalysisModule],
        scanner: Scanner,
        profile: ChallengeProfile,
        selected_modules: List[str],
    ) -> None:
        self.modules = list(modules)
        self.scanner = scanner
        self.profile = profile
        self.selected_modules = selected_modules

    def analyze(self, file_path: str) -> AnalysisSummary:
        data = read_bytes(file_path)
        module_outputs: dict[str, List[str]] = {}
        for module in self.modules:
            try:
                output = module.run(file_path, data)
                module_outputs[module.name] = output
            except Exception as exc:  # noqa: BLE001
                log.exception("Module %s failed: %s", module.name, exc)
                module_outputs[module.name] = [f"error: {exc}"]
        scan_result = self.scanner.scan_outputs(module_outputs)
        flags = [item.value for item in scan_result.confirmed]
        probable_flags = [item.value for item in scan_result.probable]
        noise_flags = [item.value for item in scan_result.noise]
        return AnalysisSummary(
            flags=flags,
            probable_flags=probable_flags,
            noise_flags=noise_flags,
            scan_result=scan_result,
            module_outputs=module_outputs,
            selected_modules=self.selected_modules,
            profile=self.profile,
        )
