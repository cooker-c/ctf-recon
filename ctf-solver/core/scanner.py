from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

from utils.flag_finder import FlagCandidate, FlagFinder


@dataclass
class ScanResult:
    confirmed: List[FlagCandidate]
    probable: List[FlagCandidate]
    noise: List[FlagCandidate]

    @property
    def all_candidates(self) -> List[FlagCandidate]:
        return [*self.confirmed, *self.probable, *self.noise]


class Scanner:
    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        self.finder = FlagFinder(patterns)

    def scan_outputs(self, outputs: Dict[str, List[str]]) -> ScanResult:
        chunks: list[tuple[str, str]] = []
        for module_name, module_outputs in outputs.items():
            for output in module_outputs:
                chunks.append((module_name, output))

        candidates = self.finder.scan_chunks(chunks)

        confirmed: List[FlagCandidate] = []
        probable: List[FlagCandidate] = []
        noise: List[FlagCandidate] = []
        for candidate in candidates:
            if candidate.score >= 75:
                confirmed.append(candidate)
            elif candidate.score >= 50:
                probable.append(candidate)
            else:
                noise.append(candidate)
        return ScanResult(confirmed=confirmed, probable=probable, noise=noise)
