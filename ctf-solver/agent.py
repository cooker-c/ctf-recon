from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print
from rich.table import Table

from config import AppConfig
from core.dispatcher import Dispatcher
from utils.file_utils import is_readable_file
from utils.logger import get_logger

app = typer.Typer(add_completion=False)
log = get_logger("ctf-agent")


@app.command()
def analyze(
    target: Path = typer.Argument(..., exists=True, readable=True, resolve_path=True, help="Challenge file to analyze"),
    modules: Optional[str] = typer.Option(None, help="Comma-separated module list (forensics,reversing,crypto,stego)"),
    flag_pattern: Optional[str] = typer.Option(None, help="Override flag regex pattern"),
    timeout: int = typer.Option(30, help="Per-tool timeout in seconds"),
) -> None:
    if not is_readable_file(target):
        raise typer.Exit(code=1)

    cfg = AppConfig()
    enabled = cfg.enabled_modules or []
    if modules:
        enabled = [m.strip() for m in modules.split(",") if m.strip()]
    patterns = list(cfg.flag_patterns)
    if flag_pattern:
        patterns.insert(0, flag_pattern)
    dispatcher = Dispatcher(enabled_modules=enabled or None, timeout=timeout or cfg.timeout, flag_patterns=patterns or None)
    analyzer = dispatcher.create_analyzer()

    summary = analyzer.analyze(str(target))

    table = Table(title="CTF-Agent Results")
    table.add_column("Module")
    table.add_column("Findings", overflow="fold")
    for module, outputs in summary.module_outputs.items():
        joined = "\n".join(outputs[:10]) or "(no output)"
        table.add_row(module, joined)
    print(table)

    if summary.flags:
        print("[bold green]Potential flags found:[/bold green]")
        for flag in summary.flags:
            print(f" - {flag}")
    else:
        print("[yellow]No flags found. Try additional modules or manual analysis.[/yellow]")


@app.command()
def version() -> None:
    print("CTF-Agent 0.1.0")


if __name__ == "__main__":
    app()
