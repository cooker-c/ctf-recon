from __future__ import annotations

import math
from typing import List

from core.analyzer import AnalysisModule
from tools.exif_tool import ExifTool
from utils.logger import get_logger

log = get_logger(__name__)


class StegoModule(AnalysisModule):
    name = "stego"
    description = "Basic stego hints via metadata and high-entropy checks."

    def __init__(self, exif_tool: ExifTool) -> None:
        self.exif_tool = exif_tool

    def run(self, file_path: str, data: bytes) -> List[str]:
        outputs: List[str] = []
        exif = self.exif_tool.run(file_path)
        if exif and exif.stdout:
            outputs.append(exif.stdout)
        outputs.append(f"entropy: {self._shannon_entropy(data):.3f}")
        return outputs

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        total = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
