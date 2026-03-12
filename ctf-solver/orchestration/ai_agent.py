from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from coordination.worker_pool import run_tasks
from core.dispatcher import DEFAULT_MODULES
from core.messages import ChallengeMetadata, PipelineResult
from core.profiler import profile_target
from orchestration.pipeline import run_pipeline
from utils.logger import get_logger

log = get_logger(__name__)


class AIAgent:
    """Heuristic orchestrator that adapts module plans per target.

    - Builds a primary plan from file profiling + user/category hints.
    - Falls back to a broad plan when no signals are found.
    - Stops early per target once a plan yields confirmed/probable flags.
    """

    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max_workers

    def _merge_unique(self, items: Iterable[str]) -> List[str]:
        seen = set()
        merged: List[str] = []
        for item in items:
            if not item:
                continue
            if item in seen:
                continue
            seen.add(item)
            merged.append(item)
        return merged

    def _category_hints(self, category: Optional[str]) -> List[str]:
        if not category:
            return []
        c = category.lower()
        if c in {"pwn", "rev", "reversing", "binary"}:
            return ["reversing", "forensics"]
        if c in {"web"}:
            return ["forensics", "stego"]
        if c in {"crypto", "cryptography"}:
            return ["crypto", "forensics"]
        if c in {"stego", "steganography"}:
            return ["stego", "forensics"]
        if c in {"forensics"}:
            return ["forensics", "stego"]
        return []

    def _description_hints(self, description: Optional[str]) -> List[str]:
        if not description:
            return []
        desc = description.lower()
        hints: List[str] = []
        if any(k in desc for k in ["encrypt", "cipher", "rsa", "aes", "xor", "base64", "hash"]):
            hints.append("crypto")
        if any(k in desc for k in ["image", "png", "jpg", "jpeg", "bmp", "gif", "stego", "lsb"]):
            hints.append("stego")
        if any(k in desc for k in ["binary", "elf", "exe", "overflow", "rop", "fmtstr", "pwn"]):
            hints.append("reversing")
        if any(k in desc for k in ["pcap", "disk", "memory", "forensic", "carve", "recover"]):
            hints.append("forensics")
        return hints

    def _plan_modules(
        self,
        target: Path,
        metadata: ChallengeMetadata,
        enabled_modules: Optional[List[str]],
    ) -> List[List[str]]:
        profile = profile_target(str(target))
        base = enabled_modules or profile.recommended_modules
        cat_hints = self._category_hints(metadata.category)
        desc_hints = self._description_hints(metadata.description)
        primary = self._merge_unique([*(base or []), *cat_hints, *desc_hints])
        # Broad fallback uses all known modules when primary is empty or too narrow
        broad = list(DEFAULT_MODULES.keys())
        plans: List[List[str]] = []
        if primary:
            plans.append(primary)
        if not primary or set(primary) != set(broad):
            plans.append(broad)
        return plans

    def _pick_best(self, results: List[Tuple[PipelineResult, List[str]]]) -> PipelineResult:
        # Prefer confirmed > probable > first
        for res, _plan in results:
            if res.confirmed_flags:
                return res
        for res, _plan in results:
            if res.probable_flags:
                return res
        return results[0][0]

    def orchestrate(
        self,
        targets: Sequence[Path],
        metadata: ChallengeMetadata,
        enabled_modules: Optional[List[str]],
        timeout: int,
        flag_patterns: Optional[List[str]] = None,
    ) -> List[PipelineResult]:
        patterns = list(flag_patterns or [])
        if metadata.flag_format:
            patterns.insert(0, metadata.flag_format)

        def worker(target_path: Path) -> PipelineResult:
            log.info("Agent: analyzing %s", target_path)
            plans = self._plan_modules(target_path, metadata, enabled_modules)
            attempt_results: List[Tuple[PipelineResult, List[str]]] = []
            for plan in plans:
                log.debug("Plan for %s: %s", target_path, plan)
                res = run_pipeline(
                    target=target_path,
                    metadata=metadata,
                    enabled_modules=plan,
                    timeout=timeout,
                    flag_patterns=patterns or None,
                )
                attempt_results.append((res, plan))
                if res.confirmed_flags or res.probable_flags:
                    break
            return self._pick_best(attempt_results)

        return run_tasks(targets, worker, max_workers=self.max_workers)
