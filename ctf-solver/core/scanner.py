from __future__ import annotations

from typing import Iterable, List

from utils.flag_finder import FlagFinder


class Scanner:
    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        self.finder = FlagFinder(patterns)

    def scan_outputs(self, outputs: Iterable[str]) -> List[str]:
        return self.finder.scan_chunks(outputs)
