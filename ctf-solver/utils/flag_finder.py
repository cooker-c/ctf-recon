from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, List, Pattern

DEFAULT_PATTERNS = [
    r"(?:flag|ctf)\{[A-Za-z0-9_!@#$%^&*()\-+=:;,.?/]{4,120}\}",
    r"[A-Z][A-Z0-9_]{1,15}\{[A-Za-z0-9_!@#$%^&*()\-+=:;,.?/]{4,120}\}",
]


@dataclass(frozen=True)
class FlagCandidate:
    value: str
    score: int
    source: str
    reason: str


class FlagFinder:
    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        pattern_list = list(patterns) if patterns else DEFAULT_PATTERNS
        self.compiled: List[Pattern[str]] = [re.compile(p) for p in pattern_list]

    def score(self, candidate: str, context: str = "") -> tuple[int, str]:
        score = 40
        reasons: list[str] = []

        if candidate.startswith("flag{") or candidate.startswith("ctf{"):
            score += 30
            reasons.append("known-prefix")

        if re.match(r"^[A-Z][A-Z0-9_]{1,15}\{", candidate):
            score += 20
            reasons.append("event-prefix")

        if any(ch.isspace() for ch in candidate):
            score -= 30
            reasons.append("contains-whitespace")

        if len(candidate) < 8 or len(candidate) > 140:
            score -= 20
            reasons.append("length-outlier")

        punctuation = sum(1 for ch in candidate if not ch.isalnum() and ch not in "{}_")
        if punctuation > max(8, len(candidate) // 3):
            score -= 20
            reasons.append("too-much-punctuation")

        lower_context = context.lower()
        if "flag" in lower_context or "correct" in lower_context or "submit" in lower_context:
            score += 10
            reasons.append("strong-context")

        if score < 0:
            score = 0
        if score > 100:
            score = 100
        return score, ",".join(reasons) if reasons else "generic"

    def scan_text(self, text: str, source: str = "unknown") -> list[FlagCandidate]:
        found: dict[str, FlagCandidate] = {}
        for pattern in self.compiled:
            for match in pattern.finditer(text):
                candidate = match.group(0)
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                context = text[line_start:line_end]
                score, reason = self.score(candidate, context=context)
                current = found.get(candidate)
                scored = FlagCandidate(value=candidate, score=score, source=source, reason=reason)
                if current is None or scored.score > current.score:
                    found[candidate] = scored
        return sorted(found.values(), key=lambda item: (-item.score, item.value))

    def scan_chunks(self, chunks: Iterable[tuple[str, str]]) -> list[FlagCandidate]:
        found: dict[str, FlagCandidate] = {}
        for source, chunk in chunks:
            for match in self.scan_text(chunk, source=source):
                current = found.get(match.value)
                if current is None or match.score > current.score:
                    found[match.value] = match
        return sorted(found.values(), key=lambda item: (-item.score, item.value))
