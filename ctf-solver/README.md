# CTF-Agent

CTF-Agent is a modular command-line helper that runs common CTF analysis techniques (forensics, reversing, crypto, stego) and scans their outputs for potential flags.

## Features
- Runs pluggable analysis modules (forensics, reversing, crypto, stego) over a target file
- Leverages common tools when available (strings, binwalk, exiftool, python-magic)
- Scans aggregated output with configurable flag regex patterns
- Extensible design so you can drop in new modules and tools later

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

## Notes
- External tools (`strings`, `binwalk`, `exiftool`) are optional; the agent falls back when missing.
- Extracted artifacts can be written under `extracted/` as modules grow.
- If you update dependencies later, run `pip install -e .` again in the same virtual environment.

## Roadmap
- Add AI-assisted module selection and pattern learning
- Integrate WebMCP for remote context gathering
- Expand toolchain (yara, zsteg, foremost) and add parallel execution
