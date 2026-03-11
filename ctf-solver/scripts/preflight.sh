#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target-file>" >&2
  exit 1
fi

target="$1"

if [[ ! -e "$target" ]]; then
  echo "[!] Target does not exist: $target" >&2
  exit 1
fi

if [[ ! -r "$target" ]]; then
  echo "[!] Target is not readable: $target" >&2
  exit 1
fi

size_bytes="$(stat -c %s "$target")"
sha256="$(sha256sum "$target" | awk '{print $1}')"
file_desc="$(file -b "$target")"

echo "[*] Preflight checks"
echo "    Path: $target"
echo "    Size: $size_bytes bytes"
echo "    SHA256: $sha256"
echo "    Type: $file_desc"

if [[ "$size_bytes" -gt $((200 * 1024 * 1024)) ]]; then
  echo "[!] File is larger than 200MB. Expect slow analysis." >&2
fi

if [[ $EUID -eq 0 ]]; then
  echo "[!] Do not run challenge files as root." >&2
  exit 1
fi

echo "[+] Preflight passed"
