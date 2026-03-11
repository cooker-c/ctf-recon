from __future__ import annotations

import json
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
    json_output: Optional[Path] = typer.Option(None, help="Write full analysis report to JSON file"),
    show_noise: bool = typer.Option(False, help="Print low-confidence flag-like strings"),
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
    analyzer = dispatcher.create_analyzer(str(target))

    summary = analyzer.analyze(str(target))

    table = Table(title="CTF-Agent Results")
    table.add_column("Module")
    table.add_column("Findings", overflow="fold")
    for module, outputs in summary.module_outputs.items():
        joined = "\n".join(outputs[:10]) or "(no output)"
        table.add_row(module, joined)
    print(table)

    print(f"[cyan]Profile:[/cyan] {summary.profile.category} ({summary.profile.mime})")
    print(f"[cyan]Modules used:[/cyan] {', '.join(summary.selected_modules)}")

    if summary.flags:
        print("[bold green]Confirmed flags:[/bold green]")
        for flag in summary.flags:
            print(f" - {flag}")
    else:
        print("[yellow]No confirmed flags found.[/yellow]")

    if summary.probable_flags:
        print("[bold yellow]Probable candidates:[/bold yellow]")
        for flag in summary.probable_flags:
            print(f" - {flag}")

    if show_noise and summary.noise_flags:
        print("[dim]Low-confidence candidates:[/dim]")
        for flag in summary.noise_flags:
            print(f" - {flag}")

    if json_output:
        report = {
            "target": str(target),
            "profile": {
                "category": summary.profile.category,
                "mime": summary.profile.mime,
                "description": summary.profile.description,
            },
            "selected_modules": summary.selected_modules,
            "confirmed_flags": summary.flags,
            "probable_flags": summary.probable_flags,
            "noise_flags": summary.noise_flags,
            "candidates": [
                {
                    "value": c.value,
                    "score": c.score,
                    "source": c.source,
                    "reason": c.reason,
                }
                for c in summary.scan_result.all_candidates
            ],
            "module_outputs": summary.module_outputs,
        }
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[green]Report written:[/green] {json_output}")


@app.command()
def version() -> None:
    print("CTF-Agent 0.1.0")


if __name__ == "__main__":
    app()
