from __future__ import annotations

from typing import Iterable, List, Sequence

from core.analyzer import Analyzer
from core.scanner import Scanner
from modules.crypto import CryptoModule
from modules.forensics import ForensicsModule
from modules.reversing import ReversingModule
from modules.stego import StegoModule
from tools.binwalk_tool import BinwalkTool
from tools.exif_tool import ExifTool
from tools.runner import ToolRunner
from tools.strings_tool import StringsTool
from utils.logger import get_logger

log = get_logger(__name__)

DEFAULT_MODULES = {
    "forensics": ForensicsModule,
    "reversing": ReversingModule,
    "crypto": CryptoModule,
    "stego": StegoModule,
}


class Dispatcher:
    def __init__(
        self,
        enabled_modules: Sequence[str] | None = None,
        timeout: int = 30,
        flag_patterns: Sequence[str] | None = None,
    ) -> None:
        self.enabled_modules = list(enabled_modules) if enabled_modules else list(DEFAULT_MODULES.keys())
        self.runner = ToolRunner(timeout=timeout)
        self.scanner = Scanner(flag_patterns)

    def build_modules(self) -> List[object]:
        strings_tool = StringsTool(self.runner)
        binwalk_tool = BinwalkTool(self.runner)
        exif_tool = ExifTool(self.runner)

        instances: List[object] = []
        for name in self.enabled_modules:
            cls = DEFAULT_MODULES.get(name)
            if not cls:
                log.warning("Unknown module requested: %s", name)
                continue
            if name == "forensics":
                instances.append(cls(exif_tool=exif_tool, binwalk_tool=binwalk_tool))
            elif name == "reversing":
                instances.append(cls(strings_tool=strings_tool, binwalk_tool=binwalk_tool))
            elif name == "crypto":
                instances.append(cls())
            elif name == "stego":
                instances.append(cls(exif_tool=exif_tool))
        return instances

    def create_analyzer(self) -> Analyzer:
        modules = self.build_modules()
        return Analyzer(modules=modules, scanner=self.scanner)
