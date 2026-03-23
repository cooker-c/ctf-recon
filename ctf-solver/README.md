# CTF Recon

LLM-guided recon pipeline for CTF files or URLs. It runs category-aware recon commands, captures stdout/stderr, and writes a Markdown report plus optional JSON for handoff to a stronger LLM.

## Features
- Auto-detects category (or use `--category`) and picks commands accordingly
- Runs recon commands with timeouts and skips missing tools gracefully
- Captures outputs, trims long sections, and summarizes quick observations
- Writes `report_<target>.md` and optional JSON with `--json`
- Optional LLM command selection via NVIDIA NIM (env `NVIDIA_API_KEY`)

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate            # Linux/Kali
python -m pip install --upgrade pip
pip install -e .                     # no required deps

# Optional: enable LLM selection (needs openai client installed)
pip install 'openai>=1.12.0'
export NVIDIA_API_KEY="nvapi-..."
```

## Usage
```bash
python3 ctf_recon.py challenge.bin --category pwn
python3 ctf_recon.py challenge.png              # auto-detects category
python3 ctf_recon.py http://chal.local --category web
```

Outputs:
- Markdown: `report_<name>.md`
- JSON (optional): `report_<name>.json` when `--json` is set

LLM behavior:
- If `NVIDIA_API_KEY` is set and `openai` is installed, the LLM suggests a subset of commands to run.
- If the key is missing or the call fails, all commands run (fallback).

## Notes
- External tools (strings, file, exiftool, binwalk, etc.) are invoked if present; missing tools are reported as "tool not found" and skipped.
- Keep your `NVIDIA_API_KEY` out of source control; set it per-shell or via a secrets manager.

## Examples
```bash
python3 ctf_recon.py vuln --category pwn
python3 ctf_recon.py traffic.pcap --category forensics --json
python3 ctf_recon.py https://challenge.ctf/site --category web
```
