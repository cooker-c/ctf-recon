from __future__ import annotations

import re
from typing import Iterable, List, Pattern

DEFAULT_PATTERNS = [
    r"flag\{[^\n\r\t}]{5,}\}",
    r"ctf\{[^\n\r\t}]{5,}\}",
    r"[A-Z0-9]{8,}\{[^\n\r\t}]{4,}\}",
    r"[A-Za-z0-9+/]{20,}={0,2}",
]


class FlagFinder:
    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        pattern_list = list(patterns) if patterns else DEFAULT_PATTERNS
        self.compiled: List[Pattern[str]] = [re.compile(p) for p in pattern_list]

    def scan_text(self, text: str) -> list[str]:
        found: set[str] = set()
        for pattern in self.compiled:
            for match in pattern.findall(text):
                found.add(match)
        return sorted(found)

    def scan_chunks(self, chunks: Iterable[str]) -> list[str]:
        found: set[str] = set()
        for chunk in chunks:
            for match in self.scan_text(chunk):
                found.add(match)
        return sorted(found)
