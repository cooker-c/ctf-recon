from __future__ import annotations

from typing import List

from core.analyzer import AnalysisModule
from tools.binwalk_tool import BinwalkTool
from tools.exif_tool import ExifTool
from tools.file_tool import analyze_file_json
from tools.runner import ToolRunner
from utils.logger import get_logger

log = get_logger(__name__)


class ForensicsModule(AnalysisModule):
    name = "forensics"
    description = "File metadata, structure scanning, and simple carving hints."

    def __init__(self, exif_tool: ExifTool, binwalk_tool: BinwalkTool, runner: ToolRunner | None = None) -> None:
        self.exif_tool = exif_tool
        self.binwalk_tool = binwalk_tool
        self.runner = runner

    def run(self, file_path: str, data: bytes) -> List[str]:
        outputs: List[str] = [analyze_file_json(file_path)]

        exif = self.exif_tool.run(file_path)
        if exif and exif.stdout:
            outputs.append(exif.stdout)

        scan = self.binwalk_tool.run_scan(file_path)
        if scan and scan.stdout:
            outputs.append(scan.stdout)
        return outputs
