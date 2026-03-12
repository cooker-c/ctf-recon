from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional

from core.dispatcher import Dispatcher
from core.messages import AttachmentRecord, ChallengeMetadata, PipelineResult
from tools.file_tool import analyze_file
from utils.logger import get_logger

log = get_logger(__name__)


def record_attachments(paths: Iterable[Path]) -> List[AttachmentRecord]:
    records: List[AttachmentRecord] = []
    for path in paths:
        info = analyze_file(path)
        records.append(
            AttachmentRecord(
                path=path,
                sha256=str(info.get("sha256", "")),
                mime=str(info.get("mime", "")),
            ),
        )
    return records


def run_pipeline(
    target: Path,
    metadata: ChallengeMetadata,
    enabled_modules: Optional[List[str]],
    timeout: int,
    flag_patterns: Optional[List[str]] = None,
) -> PipelineResult:
    patterns = list(flag_patterns or [])
    if metadata.flag_format:
        patterns.insert(0, metadata.flag_format)

    dispatcher = Dispatcher(enabled_modules=enabled_modules, timeout=timeout, flag_patterns=patterns or None)
    analyzer = dispatcher.create_analyzer(str(target))
    summary = analyzer.analyze(str(target))

    artifacts = record_attachments(metadata.attachments) if metadata.attachments else []

    return PipelineResult(
        confirmed_flags=summary.flags,
        probable_flags=summary.probable_flags,
        noise_flags=summary.noise_flags,
        module_outputs=summary.module_outputs,
        profile=summary.profile.category,
        mime=summary.profile.mime,
        description=summary.profile.description,
        selected_modules=summary.selected_modules,
        artifacts=artifacts,
    )
