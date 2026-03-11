#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target-file> [ctf-agent args...]" >&2
  echo "Example: $0 ./vuln --json-output extracted/report.json --show-noise" >&2
  exit 1
fi

target="$1"
shift || true

"$(dirname "$0")/preflight.sh" "$target"

if ! command -v ctf-agent >/dev/null 2>&1; then
  echo "[!] ctf-agent is not in PATH. Activate your venv or install via pipx." >&2
  exit 1
fi

echo "[*] Running ctf-agent analyze with a 120s hard timeout"
timeout 120s ctf-agent analyze "$target" "$@"
