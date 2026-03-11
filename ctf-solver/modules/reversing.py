from __future__ import annotations

from typing import List

from core.analyzer import AnalysisModule
from tools.binwalk_tool import BinwalkTool
from tools.strings_tool import StringsTool
from utils.logger import get_logger

log = get_logger(__name__)


class ReversingModule(AnalysisModule):
    name = "reversing"
    description = "Generic reversing heuristics (strings, headers, embedded data)."

    def __init__(self, strings_tool: StringsTool, binwalk_tool: BinwalkTool) -> None:
        self.strings_tool = strings_tool
        self.binwalk_tool = binwalk_tool

    def run(self, file_path: str, data: bytes) -> List[str]:
        results: List[str] = []
        strings = self.strings_tool.run(file_path, data)
        results.extend(strings[:200])

        binwalk_scan = self.binwalk_tool.run_scan(file_path)
        if binwalk_scan and binwalk_scan.stdout:
            results.append(binwalk_scan.stdout)
        return results
