from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from tools.file_tool import analyze_file


@dataclass
class ChallengeProfile:
    category: str
    mime: str
    description: str
    recommended_modules: List[str]


def profile_target(path: str | Path) -> ChallengeProfile:
    info = analyze_file(path)
    mime = str(info.get("mime", "unknown"))
    description = str(info.get("description", "")).lower()

    if mime.startswith("image/"):
        return ChallengeProfile("image", mime, description, ["forensics", "stego", "crypto"])
    if mime.startswith("audio/") or mime.startswith("video/"):
        return ChallengeProfile("media", mime, description, ["stego", "forensics", "crypto"])
    if "elf" in description or "pe32" in description or "executable" in mime:
        return ChallengeProfile("binary", mime, description, ["reversing", "forensics", "crypto"])
    if "zip" in mime or "gzip" in mime or "tar" in mime or "archive" in description:
        return ChallengeProfile("archive", mime, description, ["forensics", "reversing", "crypto"])
    if mime.startswith("text/") or "json" in mime or "javascript" in mime:
        return ChallengeProfile("text", mime, description, ["reversing", "crypto", "forensics"])
    return ChallengeProfile("generic", mime, description, ["forensics", "reversing", "crypto", "stego"])
