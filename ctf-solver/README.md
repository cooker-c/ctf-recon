# CTF Recon CLI

This directory contains the installable Python package for CTF Recon.

For the full project overview, safety notes, and contribution workflow, see the repository [README](../README.md).

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

## Examples

```bash
ctf-recon challenge.bin --category pwn
ctf-recon traffic.pcap --category forensics --json --output-dir reports
ctf-recon https://challenge.ctf/site --category web
ctf-recon 127.0.0.1:31337 --title "Warmup service"
```

Dynamic tracing commands that execute local binaries are disabled by default. Use `--allow-execution` only in an isolated CTF VM or container.

## Development

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m bandit -q -r ctf_recon.py
```
