# CTF-Agent

CTF-Agent is a modular command-line helper that runs common CTF analysis techniques (forensics, reversing, crypto, stego) and scans their outputs for potential flags.

## Features
- Runs pluggable analysis modules (forensics, reversing, crypto, stego) over a target file
- Leverages common tools when available (strings, binwalk, exiftool, python-magic)
- Profiles the target and selects modules based on challenge type
- Scores flag candidates and separates them into confirmed/probable/noise buckets
- Supports JSON report output for repeatable triage and automation
- Extensible design so you can drop in new modules and tools later
- Layered architecture with structured message passing:
  - Ingestion (web) → Orchestration → Execution (local/SSH) → Coordination (worker pool) → Output (submission)

## Quickstart
1. Clone and enter the project:
  ```bash
  git clone https://github.com/cooker-c/ctf-solver.git
  cd ctf-solver/ctf-solver
  ```
2. Create and activate a virtual environment:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate  # Linux/Kali
  ```
  ```powershell
  py -m venv .venv
  .venv\Scripts\Activate.ps1  # Windows PowerShell
  ```
3. Install all Python dependencies in one step:
  ```bash
  python -m pip install --upgrade pip
  pip install -e .
  ```
4. Optional but recommended external tools:
  ```bash
  sudo apt update
  sudo apt install -y binwalk exiftool binutils file
  ```
5. Run the analyzer on a file:
  ```bash
  ctf-agent analyze path/to/challenge.bin
  ```
6. Run the pipeline with metadata hints:
  ```bash
  ctf-agent pipeline path/to/challenge.bin --flag-format "flag{.*}" --category pwn --json-output extracted/report.json
  ```

## Safe workflow for unknown/vulnerable files (Linux/Kali)
1. Make scripts executable once:
  ```bash
  chmod +x scripts/*.sh
  ```
2. Run preflight + analysis with hard timeout:
  ```bash
  ./scripts/safe-analyze.sh ./vuln --json-output extracted/vuln-report.json
  ```
3. If you intentionally need to execute the binary, run with guardrails:
  ```bash
  ./scripts/run-vuln-safely.sh ./vuln
  ```
  Safety measures include: no root execution, preflight checks, temporary isolated copy, timeout, and network namespace isolation when `unshare` is available.

## One-command setup (Kali/Linux)
From the project root:
```bash
python3 -m venv .venv && source .venv/bin/activate && python -m pip install --upgrade pip && pip install -e . && sudo apt update && sudo apt install -y binwalk exiftool binutils file
```

## Verify installation
```bash
ctf-agent version
python -c "import agent, config, core, modules, tools, utils; print('imports-ok')"
```

## CLI
- Analyze a file with selected modules:
  ```bash
  ctf-agent analyze challenge.jpg --modules forensics,stego
  ```
- Override flag pattern:
  ```bash
  ctf-agent analyze challenge.bin --flag-pattern "flag\{[^}]+\}"
  ```
- Write machine-readable report and include low-confidence strings:
  ```bash
  ctf-agent analyze challenge.bin --json-output extracted/report.json --show-noise
  ```
- Full pipeline with metadata hints:
  ```bash
  ctf-agent pipeline challenge.bin --category rev --description "ELF, stripped" --flag-format "flag{[A-Za-z0-9_]+}" --json-output extracted/pipeline.json
  ```
- Agent fan-out across multiple files (parallel):
  ```bash
  ctf-agent agent challenge1.bin challenge2.bin --category pwn --flag-format "flag{.*}" --max-workers 4 --json-output extracted/agent.json
  ```
- Agent with ingestion (pull page + attachments):
  ```bash
  ctf-agent agent challenge.bin --page-url https://ctf.local/chal/123 --attachment-url https://ctf.local/files/chal123.zip --json-output extracted/agent.json
  ```
- Show version:
  ```bash
  ctf-agent version
  ```

## Configuration
Environment variables (prefixed with `CTF_AGENT_`) override defaults:
- `CTF_AGENT_ENABLED_MODULES` (comma-separated) — modules to run
- `CTF_AGENT_FLAG_PATTERNS` — custom flag regex patterns
- `CTF_AGENT_TIMEOUT` — per-tool timeout seconds

## Modules
- Forensics: file metadata (magic), exif, binwalk scan
- Reversing: strings extraction plus binwalk hints
- Crypto: heuristics for hex/base64 blobs
- Stego: metadata plus entropy clue

## Phase 1 behavior
- Auto-profiling chooses a module set based on file type (binary/image/archive/text/media).
- Flag candidates are confidence-scored and reported separately:
  - `Confirmed` (high confidence)
  - `Probable` (needs manual validation)
  - `Noise` (low-confidence strings, hidden unless `--show-noise`)
- JSON output includes candidate score, source module, and scoring reason.

## Notes
- External tools (`strings`, `binwalk`, `exiftool`) are optional; the agent falls back when missing.
- Extracted artifacts can be written under `extracted/` as modules grow.
- If you update dependencies later, run `pip install -e .` again in the same virtual environment.

## Roadmap
- Add AI-assisted module selection and pattern learning
- Integrate WebMCP for remote context gathering
- Expand toolchain (yara, zsteg, foremost) and add parallel execution
