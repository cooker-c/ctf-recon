from __future__ import annotations

from typing import List

from core.analyzer import AnalysisModule
from tools.binwalk_tool import BinwalkTool
from tools.strings_tool import StringsTool
from tools.runner import ToolRunner
from utils.logger import get_logger

log = get_logger(__name__)


class ReversingModule(AnalysisModule):
    name = "reversing"
    description = "Reversing heuristics with strings, structure scans, and lightweight binary triage."

    def __init__(self, strings_tool: StringsTool, binwalk_tool: BinwalkTool, runner: ToolRunner) -> None:
        self.strings_tool = strings_tool
        self.binwalk_tool = binwalk_tool
        self.runner = runner

    def _run_cmd(self, command: List[str], limit_lines: int = 200) -> str:
        if not self.runner.is_available(command[0]):
            return f"{command[0]} not available"
        result = self.runner.run(command)
        if not result.ok:
            return f"{result.command} -> failed ({result.exit_code}): {result.stderr.strip()}"
        lines = result.stdout.splitlines()
        return "\n".join(lines[:limit_lines])

    def run(self, file_path: str, data: bytes) -> List[str]:
        results: List[str] = []

        # Strings baseline
        strings = self.strings_tool.run(file_path, data)
        results.append("\n".join(strings[:200]))

        # Structural/embedded data scan
        binwalk_scan = self.binwalk_tool.run_scan(file_path)
        if binwalk_scan and binwalk_scan.stdout:
            results.append(binwalk_scan.stdout)

        # ELF triage (lightweight)
        results.append(self._run_cmd(["file", file_path], limit_lines=50))
        results.append(self._run_cmd(["readelf", "-a", "-W", file_path], limit_lines=200))
        results.append(self._run_cmd(["objdump", "-d", "--no-show-raw-insn", file_path], limit_lines=200))

        # Security posture (optional tool)
        results.append(self._run_cmd(["checksec", "--file", file_path], limit_lines=80))

        # Basic gdb introspection (no execution)
        results.append(
            self._run_cmd(
                [
                    "gdb",
                    "-q",
                    "-batch",
                    "-ex",
                    "info files",
                    "-ex",
                    "info functions",
                    file_path,
                ],
                limit_lines=200,
            )
        )

        return results
