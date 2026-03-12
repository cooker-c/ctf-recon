from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ChallengeMetadata:
    source_url: Optional[str]
    title: str
    category: Optional[str]
    description: Optional[str]
    flag_format: Optional[str]
    attachments: List[Path] = field(default_factory=list)


@dataclass
class AttachmentRecord:
    path: Path
    sha256: str
    mime: Optional[str] = None


@dataclass
class ExecutionPlan:
    profile: str
    selected_modules: List[str]
    timeout_seconds: int


@dataclass
class ModuleTask:
    module: str
    target: Path
    metadata: ChallengeMetadata


@dataclass
class TaskResult:
    module: str
    output: List[str]
    error: Optional[str] = None


@dataclass
class PipelineResult:
    confirmed_flags: List[str]
    probable_flags: List[str]
    noise_flags: List[str]
    module_outputs: Dict[str, List[str]]
    profile: str
    mime: str
    description: str
    selected_modules: List[str]
    artifacts: List[AttachmentRecord] = field(default_factory=list)


@dataclass
class SubmissionResult:
    submitted: bool
    flag: Optional[str]
    response_status: Optional[int]
    response_body: Optional[str]
    error: Optional[str] = None
