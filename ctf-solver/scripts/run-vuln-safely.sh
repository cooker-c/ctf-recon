#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <executable-file> [args...]" >&2
  echo "Example: $0 ./vuln" >&2
  exit 1
fi

bin="$1"
shift || true

"$(dirname "$0")/preflight.sh" "$bin"

if [[ ! -x "$bin" ]]; then
  echo "[*] Target is not executable. Attempting chmod +x"
  chmod +x "$bin"
fi

if [[ $EUID -eq 0 ]]; then
  echo "[!] Refusing to run as root." >&2
  exit 1
fi

echo "[*] Safety controls"
echo "    - core dumps disabled"
echo "    - 30s execution timeout"
echo "    - clean temporary working directory"

ulimit -c 0
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

cp "$bin" "$workdir/target.bin"
chmod 700 "$workdir/target.bin"

if command -v unshare >/dev/null 2>&1; then
  echo "[*] Running with isolated network namespace (unshare -n)"
  if ! timeout 30s unshare -n -- "$workdir/target.bin" "$@"; then
    echo "[!] unshare execution failed; falling back to timeout-only run" >&2
    timeout 30s "$workdir/target.bin" "$@"
  fi
else
  echo "[*] unshare not found; running with timeout only"
  timeout 30s "$workdir/target.bin" "$@"
fi
