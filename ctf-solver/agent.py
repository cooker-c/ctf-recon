from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich import print
from rich.table import Table

from config import AppConfig
from core.dispatcher import Dispatcher
from core.messages import ChallengeMetadata
from ingestion.web_ingestor import ingest_from_url
from orchestration.ai_agent import AIAgent
from orchestration.pipeline import run_pipeline
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
def pipeline(
    target: Path = typer.Argument(..., exists=True, readable=True, resolve_path=True, help="Challenge file to analyze"),
    modules: Optional[str] = typer.Option(None, help="Comma-separated module list (forensics,reversing,crypto,stego)"),
    flag_format: Optional[str] = typer.Option(None, help="Flag format hint (regex or known prefix)"),
    category: Optional[str] = typer.Option(None, help="Challenge category hint (pwn, web, rev, forensics, crypto, misc)"),
    description: Optional[str] = typer.Option(None, help="Short challenge description to guide heuristics"),
    timeout: int = typer.Option(30, help="Per-tool timeout in seconds"),
    json_output: Optional[Path] = typer.Option(None, help="Write full pipeline report to JSON file"),
    show_noise: bool = typer.Option(False, help="Print low-confidence flag-like strings"),
) -> None:
    if not is_readable_file(target):
        raise typer.Exit(code=1)

    cfg = AppConfig()
    enabled = cfg.enabled_modules or []
    if modules:
        enabled = [m.strip() for m in modules.split(",") if m.strip()]

    metadata = ChallengeMetadata(
        source_url=None,
        title=target.name,
        category=category,
        description=description,
        flag_format=flag_format,
        attachments=[target],
    )

    patterns = list(cfg.flag_patterns)
    if flag_format:
        patterns.insert(0, flag_format)

    result = run_pipeline(
        target=target,
        metadata=metadata,
        enabled_modules=enabled or None,
        timeout=timeout or cfg.timeout,
        flag_patterns=patterns or None,
    )

    table = Table(title="CTF-Agent Pipeline")
    table.add_column("Module")
    table.add_column("Findings", overflow="fold")
    for module, outputs in result.module_outputs.items():
        joined = "\n".join(outputs[:10]) or "(no output)"
        table.add_row(module, joined)
    print(table)

    print(f"[cyan]Profile:[/cyan] {result.profile} ({result.mime})")
    print(f"[cyan]Modules used:[/cyan] {', '.join(result.selected_modules)}")

    if result.confirmed_flags:
        print("[bold green]Confirmed flags:[/bold green]")
        for flag in result.confirmed_flags:
            print(f" - {flag}")
    else:
        print("[yellow]No confirmed flags found.[/yellow]")

    if result.probable_flags:
        print("[bold yellow]Probable candidates:[/bold yellow]")
        for flag in result.probable_flags:
            print(f" - {flag}")

    if show_noise and result.noise_flags:
        print("[dim]Low-confidence candidates:[/dim]")
        for flag in result.noise_flags:
            print(f" - {flag}")

    if json_output:
        report = {
            "target": str(target),
            "profile": result.profile,
            "mime": result.mime,
            "description": result.description,
            "selected_modules": result.selected_modules,
            "confirmed_flags": result.confirmed_flags,
            "probable_flags": result.probable_flags,
            "noise_flags": result.noise_flags,
            "module_outputs": result.module_outputs,
            "artifacts": [
                {"path": str(a.path), "sha256": a.sha256, "mime": a.mime}
                for a in result.artifacts
            ],
        }
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[green]Pipeline report written:[/green] {json_output}")


@app.command(name="agent")
def agent_command(
    targets: Optional[List[Path]] = typer.Argument(
        None,
        exists=True,
        readable=True,
        resolve_path=True,
        help="One or more challenge files (positional)",
    ),
    input: Optional[List[Path]] = typer.Option(
        None,
        "--input",
        "-i",
        exists=True,
        readable=True,
        resolve_path=True,
        help="One or more challenge files (option form)",
    ),
    modules: Optional[str] = typer.Option(None, help="Comma-separated module list (forensics,reversing,crypto,stego)"),
    flag_format: Optional[str] = typer.Option(None, help="Flag format hint (regex or known prefix)"),
    category: Optional[str] = typer.Option(None, help="Challenge category hint (pwn, web, rev, forensics, crypto, misc)"),
    description: Optional[str] = typer.Option(None, help="Short challenge description to guide heuristics"),
    page_url: Optional[str] = typer.Option(None, help="Optional challenge page URL to ingest metadata"),
    attachment_url: List[str] = typer.Option([], help="Attachment URLs to download and include"),
    timeout: int = typer.Option(30, help="Per-tool timeout in seconds"),
    max_workers: int = typer.Option(4, help="Parallel workers for multi-file analysis"),
    json_output: Optional[Path] = typer.Option(None, help="Write combined agent report to JSON file"),
    show_noise: bool = typer.Option(False, help="Print low-confidence flag-like strings"),
) -> None:
    cfg = AppConfig()
    enabled = cfg.enabled_modules or []
    if modules:
        enabled = [m.strip() for m in modules.split(",") if m.strip()]

    attachment_urls = attachment_url or []
    download_dir = Path("extracted/ingested")

    # Combine positional and option-based inputs
    final_targets: List[Path] = []
    if targets:
        final_targets.extend(targets)
    if input:
        final_targets.extend(input)
    if not final_targets:
        typer.echo("[red]No targets provided. Use positional targets or --input/-i.[/red]")
        raise typer.Exit(code=1)

    if page_url:
        meta = ingest_from_url(page_url, attachment_urls if attachment_urls else None, download_dir)
        # Merge manual hints
        meta.flag_format = flag_format or meta.flag_format
        meta.category = category or meta.category
        meta.description = description or meta.description
        # Append downloaded attachments to targets
        final_targets = final_targets + [Path(p) for p in meta.attachments]
    else:
        meta = ChallengeMetadata(
            source_url=None,
            title=final_targets[0].name if final_targets else "challenge",
            category=category,
            description=description,
            flag_format=flag_format,
            attachments=final_targets,
        )

    patterns = list(cfg.flag_patterns)
    if meta.flag_format:
        patterns.insert(0, meta.flag_format)

    agent = AIAgent(max_workers=max_workers)
    results = agent.orchestrate(
        targets=final_targets,
        metadata=meta,
        enabled_modules=enabled or None,
        timeout=timeout or cfg.timeout,
        flag_patterns=patterns or None,
    )

    # Aggregate console output
    for res in results:
        print(f"[magenta]=== Target:[/magenta] {res.artifacts[0].path if res.artifacts else 'unknown'}")
        table = Table(title="Agent Run")
        table.add_column("Module")
        table.add_column("Findings", overflow="fold")
        for module, outputs in res.module_outputs.items():
            joined = "\n".join(outputs[:10]) or "(no output)"
            table.add_row(module, joined)
        print(table)

        print(f"[cyan]Profile:[/cyan] {res.profile} ({res.mime})")
        print(f"[cyan]Modules used:[/cyan] {', '.join(res.selected_modules)}")

        if res.confirmed_flags:
            print("[bold green]Confirmed flags:[/bold green]")
            for flag in res.confirmed_flags:
                print(f" - {flag}")
        else:
            print("[yellow]No confirmed flags found.[/yellow]")

        if res.probable_flags:
            print("[bold yellow]Probable candidates:[/bold yellow]")
            for flag in res.probable_flags:
                print(f" - {flag}")

        if show_noise and res.noise_flags:
            print("[dim]Low-confidence candidates:[/dim]")
            for flag in res.noise_flags:
                print(f" - {flag}")

    if json_output:
        combined = []
        for res in results:
            combined.append(
                {
                    "profile": res.profile,
                    "mime": res.mime,
                    "description": res.description,
                    "selected_modules": res.selected_modules,
                    "confirmed_flags": res.confirmed_flags,
                    "probable_flags": res.probable_flags,
                    "noise_flags": res.noise_flags,
                    "module_outputs": res.module_outputs,
                    "artifacts": [
                        {"path": str(a.path), "sha256": a.sha256, "mime": a.mime}
                        for a in res.artifacts
                    ],
                }
            )
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(combined, indent=2), encoding="utf-8")
        print(f"[green]Agent combined report written:[/green] {json_output}")


@app.command()
def version() -> None:
    print("CTF-Agent 0.1.0")


if __name__ == "__main__":
    app()
