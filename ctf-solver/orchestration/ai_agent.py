from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence

from coordination.worker_pool import run_tasks
from core.messages import ChallengeMetadata, PipelineResult
from orchestration.pipeline import run_pipeline
from utils.logger import get_logger

log = get_logger(__name__)


class AIAgent:
    """
    Rule-based orchestrator to fan out analysis across multiple files in parallel.
    This is a placeholder for a future LLM-driven planner; it prioritizes breadth-first
    coverage using existing module profiles and metadata hints.
    """

    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max_workers

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
            return run_pipeline(
                target=target_path,
                metadata=metadata,
                enabled_modules=enabled_modules,
                timeout=timeout,
                flag_patterns=patterns or None,
            )

        return run_tasks(targets, worker, max_workers=self.max_workers)
