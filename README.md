# CTF Recon

CTF Recon is a Python CLI that runs a focused reconnaissance pass over CTF challenge files, URLs, or `host:port` services, then writes clean Markdown and optional JSON reports for manual solving or LLM-assisted follow-up.

It is designed for students, CTF teams, and security learners who want repeatable first-pass analysis without memorizing every tool flag.

## Highlights

- Auto-detects likely challenge category: `crypto`, `pwn`, `web`, `forensics`, `rev`, or `misc`
- Runs category-aware commands and skips missing tools gracefully
- Produces Markdown reports with observations, tool output, suggested next steps, and a deep-analysis prompt
- Supports optional JSON output for automation or downstream agents
- Supports optional NVIDIA NIM analysis through the OpenAI-compatible SDK
- Uses safer defaults: local binaries are not executed unless `--allow-execution` is explicitly set
- Includes tests, linting, Bandit security scanning, and GitHub Actions CI

## Repository Layout

```text
.
|-- ctf-solver/                 # Python package and CLI source
|   |-- ctf_recon.py
|   |-- pyproject.toml
|   |-- README.md
|   `-- tests/
|-- .github/workflows/ci.yml    # lint, tests, security scan
|-- CTF_Solver_Architecture.pdf
|-- CONTRIBUTING.md
|-- LICENSE
`-- SECURITY.md
```

## Installation

From the repository root:

```bash
cd ctf-solver
python -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Optional LLM support:

```bash
python -m pip install -e ".[llm]"
export NVIDIA_API_KEY="nvapi-..."   # Windows PowerShell: $env:NVIDIA_API_KEY="nvapi-..."
```

Development setup:

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
ctf-recon challenge.bin --category pwn
ctf-recon traffic.pcap --category forensics --json
ctf-recon https://challenge.ctf/site --category web
ctf-recon 127.0.0.1:31337 --title "Warmup service"
```

You can also run the script directly:

```bash
python ctf_recon.py challenge.png --json --output-dir reports
```

Common options:

```text
--category           Optional category hint: crypto, pwn, web, forensics, rev, misc
--json               Also write a JSON report
--output-dir DIR     Directory for generated reports
--title TEXT         Challenge title included in prompts/reports
--description TEXT   Challenge description included in prompts/reports
--allow-execution    Permit ltrace/strace commands that execute local binaries
```

## Output

Reports are written as:

```text
report_<target>.md
report_<target>.json   # only when --json is used
report_combined.md     # when multiple targets are analyzed together
```

Each Markdown report includes:

- target metadata and SHA-256 hash for files
- quick observations and flag-like strings found in output
- command output with long sections truncated for readability
- suggested next steps by category
- a deep-analysis prompt suitable for a stronger LLM
- optional NVIDIA NIM analysis when configured

## External Tools

CTF Recon works best on Kali Linux or a CTF VM with common tools installed. It will still run without them and mark missing tools in the report.

Useful tools include:

- `file`, `strings`, `xxd`, `sha256sum`
- `exiftool`, `binwalk`, `foremost`, `steghide`, `zsteg`
- `checksec`, `readelf`, `nm`, `objdump`, `rabin2`
- `curl`, `whatweb`, `nc`, `tshark`

## Safety Notes

Challenge files can be hostile. By default, CTF Recon avoids dynamic tracing commands that execute local binaries. Use `--allow-execution` only inside a sandboxed VM or container.

The tool may call network utilities for URL and `host:port` targets. Only scan systems you own or have explicit permission to test.

Keep `NVIDIA_API_KEY` and any challenge credentials out of source control. Generated reports can contain secrets discovered during recon, so review before sharing.

## Quality Checks

```bash
cd ctf-solver
python -m ruff check .
python -m pytest -q
python -m bandit -q -r ctf_recon.py
```

GitHub Actions runs the same checks on Python 3.10, 3.11, and 3.12.

## Troubleshooting

`tool not found` in the report means the required external tool is not installed or not on `PATH`. Install the tool in your CTF environment and run the command again.

`Status: failed (NVIDIA_API_KEY missing)` means local recon completed, but optional LLM analysis was skipped. Set `NVIDIA_API_KEY` and install `.[llm]` to enable it.

If a report filename looks different from the target, unsafe path and URL characters were normalized so the file works across operating systems.

## License

This project is released under the GPL-3.0-or-later license. See [LICENSE](LICENSE).
