from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Protocol

from core.scanner import Scanner
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
    module_outputs: dict[str, List[str]]


class Analyzer:
    def __init__(self, modules: Iterable[AnalysisModule], scanner: Scanner) -> None:
        self.modules = list(modules)
        self.scanner = scanner

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
        flags = self.scanner.scan_outputs(output for output_list in module_outputs.values() for output in output_list)
        return AnalysisSummary(flags=flags, module_outputs=module_outputs)
