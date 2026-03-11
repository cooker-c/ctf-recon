from __future__ import annotations

import logging
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


_console: Optional[Console] = None


def get_logger(name: str = "ctf-agent", level: int = logging.INFO) -> logging.Logger:
    global _console
    if _console is None:
        _console = Console()
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = RichHandler(console=_console, rich_tracebacks=True, show_path=False)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
