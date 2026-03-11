from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    flag_patterns: List[str] = Field(default_factory=lambda: [])
    enabled_modules: List[str] = Field(default_factory=lambda: [])
    output_dir: Path = Path("extracted")
    timeout: int = 30

    class Config:
        env_prefix = "CTF_AGENT_"
        case_sensitive = False
