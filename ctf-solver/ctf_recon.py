#!/usr/bin/env python3
"""CTF recon helper.

Runs lightweight recon commands against a challenge file or URL and produces
structured Markdown/JSON reports suitable for handoff to a stronger LLM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

# Default timeouts (seconds)
COMMAND_TIMEOUT = 10
EXEC_TIMEOUT = 5  # for ltrace/strace


def is_url(target: str) -> bool:
    parsed = urlparse(target)
    return bool(parsed.scheme and parsed.netloc)


def sha256sum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_category(target: str, provided: Optional[str], magic_desc: Optional[str]) -> str:
    if provided:
        return provided.lower()
    if is_url(target):
        return "web"

    path = Path(target)
    ext = path.suffix.lower()
    ext_map = {
        ".pcap": "forensics",
        ".pcapng": "forensics",
        ".png": "forensics",
        ".jpg": "forensics",
        ".jpeg": "forensics",
        ".bmp": "forensics",
        ".gif": "forensics",
        ".wav": "forensics",
        ".mp3": "forensics",
        ".zip": "forensics",
        ".gz": "forensics",
        ".tgz": "forensics",
        ".xz": "forensics",
        ".7z": "forensics",
        ".rar": "forensics",
        ".pem": "crypto",
        ".key": "crypto",
        ".enc": "crypto",
        ".der": "crypto",
        ".crt": "crypto",
        ".so": "pwn",
        ".bin": "pwn",
        ".elf": "pwn",
        ".exe": "pwn",
    }
    if ext in ext_map:
        return ext_map[ext]

    desc = (magic_desc or "").lower()
    if any(k in desc for k in ["elf", "executable", "pe32"]):
        return "pwn"
    if any(k in desc for k in ["pcap", "capture", "network"]):
        return "forensics"
    if any(k in desc for k in ["png", "jpeg", "image", "bitmap"]):
        return "forensics"
    if any(k in desc for k in ["certificate", "rsa", "private key", "public key"]):
        return "crypto"
    return "misc"


def tool_available(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(cmd: Sequence[str] | str, timeout: int = COMMAND_TIMEOUT, cwd: Optional[str] = None) -> Dict[str, str]:
    # Determine tool availability for shell pipelines by checking first token
    if isinstance(cmd, str):
        first = cmd.split()[0]
        if "|" in cmd:
            first = cmd.split("|")[0].strip().split()[0]
        if not tool_available(first):
            return {"status": "tool not found", "stdout": "", "stderr": ""}
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            return {
                "status": "ok" if proc.returncode == 0 else f"exit {proc.returncode}",
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except subprocess.TimeoutExpired as exc:
            return {"status": "timed out", "stdout": exc.stdout or "", "stderr": exc.stderr or ""}
    else:
        if not cmd:
            return {"status": "invalid", "stdout": "", "stderr": ""}
        if not tool_available(cmd[0]):
            return {"status": "tool not found", "stdout": "", "stderr": ""}
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            return {
                "status": "ok" if proc.returncode == 0 else f"exit {proc.returncode}",
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except subprocess.TimeoutExpired as exc:
            return {"status": "timed out", "stdout": exc.stdout or "", "stderr": exc.stderr or ""}


def truncate_output(text: str, max_lines: int = 100, head: int = 50, tail: int = 10) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join([*lines[:head], "...<truncated>...", *lines[-tail:]])


def flag_like_strings(outputs: Dict[str, Dict[str, str]]) -> List[str]:
    pattern = re.compile(r"(flag|ctf)\{[^}]{4,120}\}", re.IGNORECASE)
    found: List[str] = []
    for tool, res in outputs.items():
        for text in (res.get("stdout", ""), res.get("stderr", "")):
            for match in pattern.findall(text):
                if match not in found:
                    found.append(match)
    return found


def clean_json(text: str) -> str:
    """Strip markdown fences and return the first JSON object block."""
    cleaned = text.strip()
    cleaned = cleaned.replace("```json", "```")
    cleaned = cleaned.replace("```", "")
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    return match.group(0) if match else cleaned


def call_llm(prompt: str) -> Optional[str]:
    """Call NVIDIA NIM backend; return raw text or None on any failure."""
    api_key = os.getenv("NVIDIA_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return None

    try:
        client = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=api_key)
        completion = client.chat.completions.create(
            model="tiiuae/falcon3-7b-instruct",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            top_p=0.7,
            max_tokens=1024,
            stream=True,
        )
        chunks: List[str] = []
        for chunk in completion:
            delta = chunk.choices[0].delta.content
            if delta:
                chunks.append(delta)
        return "".join(chunks)
    except Exception:
        return None


def select_commands_with_llm(category: str, target: str, cmds: List[Tuple[str, Sequence[str] | str, int]]) -> List[Tuple[str, Sequence[str] | str, int]]:
    """Ask LLM to pick commands; fallback to full list on any issue."""
    prompt_lines = [
        "You are selecting recon commands for a CTF challenge.",
        f"Category: {category}",
        f"Target: {target}",
        "Return JSON with a 'commands' array of command names to run (subset is fine).",
        "Available commands (name: shell):",
    ]
    for name, cmd, _timeout in cmds:
        rendered = cmd if isinstance(cmd, str) else " ".join(cmd)
        prompt_lines.append(f"- {name}: {rendered}")
    prompt_lines.append("Example JSON: {\"commands\": [\"file\", \"strings_grep\"]}")
    raw = call_llm("\n".join(prompt_lines))
    if not raw:
        return cmds
    try:
        payload = json.loads(clean_json(raw))
        selected: List[str] = payload.get("commands", []) if isinstance(payload, dict) else []
        if not selected:
            return cmds
        chosen = [item for item in cmds if item[0] in selected]
        return chosen or cmds
    except Exception:
        return cmds


def gather_commands(category: str, target: str, is_url_target: bool) -> List[Tuple[str, Sequence[str] | str, int]]:
    cmds: List[Tuple[str, Sequence[str] | str, int]] = []

    always_file_cmds: List[Tuple[str, str]] = [
        ("file", f"file {shlex.quote(target)}"),
        ("strings_grep", f"strings {shlex.quote(target)} | grep -i 'flag\\|ctf\\|key\\|password\\|secret'"),
        ("xxd_head", f"xxd {shlex.quote(target)} | head -40"),
        ("sha256sum", f"sha256sum {shlex.quote(target)}"),
        ("exiftool", f"exiftool {shlex.quote(target)}"),
    ]

    always_url_cmds: List[Tuple[str, str]] = [
        ("curl_head", f"curl -I {shlex.quote(target)}"),
    ]

    if is_url_target:
        cmds.extend([(name, cmd, COMMAND_TIMEOUT) for name, cmd in always_url_cmds])
    else:
        cmds.extend([(name, cmd, COMMAND_TIMEOUT) for name, cmd in always_file_cmds])

    if category in {"pwn", "binary", "rev", "reversing"}:
        cmds.extend(
            [
                ("checksec", ["checksec", f"--file={target}"], COMMAND_TIMEOUT),
                ("readelf", ["readelf", "-a", target], COMMAND_TIMEOUT),
                ("nm", ["nm", target], COMMAND_TIMEOUT),
                ("ltrace", ["ltrace", f"./{Path(target).name}"], EXEC_TIMEOUT),
                ("strace", ["strace", f"./{Path(target).name}"], EXEC_TIMEOUT),
            ]
        )
    if category in {"forensics"}:
        cmds.extend(
            [
                ("binwalk", ["binwalk", target], COMMAND_TIMEOUT),
                ("binwalk_extract", ["binwalk", "-e", target], COMMAND_TIMEOUT),
                ("foremost", ["foremost", "-i", target], COMMAND_TIMEOUT),
                ("steghide_info", ["steghide", "info", target], COMMAND_TIMEOUT),
                ("zsteg", ["zsteg", target], COMMAND_TIMEOUT),
            ]
        )
    if category in {"crypto"}:
        cmds.extend(
            [
                ("openssl_asn1", f"openssl asn1parse -in {shlex.quote(target)}", COMMAND_TIMEOUT),
                ("base64_decode", f"base64 -d {shlex.quote(target)}", COMMAND_TIMEOUT),
                ("xxd_full", f"xxd {shlex.quote(target)}", COMMAND_TIMEOUT),
                (
                    "python_detect_encoding",
                    "python3 - <<'PY'\nimport sys, codecs, base64, binascii\nfrom pathlib import Path\ndata = Path(sys.argv[1]).read_bytes()\nprint('len', len(data))\ntry:\n    print('base64?', base64.b64decode(data, validate=True)[:80])\nexcept Exception as e:\n    print('base64? no', e)\ntry:\n    print('hex?', binascii.unhexlify(data.strip())[:80])\nexcept Exception as e:\n    print('hex? no', e)\ntry:\n    decoded = codecs.decode(data.decode(errors='ignore'), 'rot_13')\n    print('rot13 sample:', decoded[:120])\nexcept Exception as e:\n    print('rot13? no', e)\nPY\n" + shlex.quote(target),
                    COMMAND_TIMEOUT,
                ),
            ]
        )
    if category in {"web"}:
        cmds.extend(
            [
                ("curl_headers", f"curl -I {shlex.quote(target)}", COMMAND_TIMEOUT),
                ("curl_grep", f"curl -s {shlex.quote(target)} | grep -i 'flag\\|comment\\|todo\\|key'", COMMAND_TIMEOUT),
                ("whatweb", ["whatweb", target], COMMAND_TIMEOUT),
                ("robots", f"curl {shlex.quote(target)}/robots.txt", COMMAND_TIMEOUT),
                ("git_head", f"curl {shlex.quote(target)}/.git/HEAD", COMMAND_TIMEOUT),
            ]
        )
    if category in {"forensics", "misc", "pwn", "rev", "reversing"}:
        # PCAP/Network heuristics if applicable
        if target.lower().endswith((".pcap", ".pcapng")):
            cmds.extend(
                [
                    ("tshark_summary", ["tshark", "-r", target, "-q", "-z", "io,phs"], COMMAND_TIMEOUT),
                    (
                        "tshark_http_uris",
                        ["tshark", "-r", target, "-Y", "http", "-T", "fields", "-e", "http.request.uri"],
                        COMMAND_TIMEOUT,
                    ),
                    ("tshark_follow", ["tshark", "-r", target, "-z", "follow,tcp,ascii,0"], COMMAND_TIMEOUT),
                ]
            )
    if category in {"rev", "reversing", "pwn", "binary"}:
        cmds.extend(
            [
                ("strings_full", ["strings", target], COMMAND_TIMEOUT),
                ("rabin2_info", ["rabin2", "-I", target], COMMAND_TIMEOUT),
                ("rabin2_symbols", ["rabin2", "-s", target], COMMAND_TIMEOUT),
                ("objdump", f"objdump -d {shlex.quote(target)} | head -100", COMMAND_TIMEOUT),
            ]
        )
    return cmds


def guess_magic(target: str) -> Optional[str]:
    if is_url(target):
        return None
    if not tool_available("file"):
        return None
    res = run_command(["file", "-b", target])
    if res["status"] == "ok":
        return res["stdout"].strip()
    return None


def build_observations(
    target: str,
    magic_desc: Optional[str],
    outputs: Dict[str, Dict[str, str]],
    flag_hits: List[str],
) -> List[str]:
    obs: List[str] = []
    if flag_hits:
        obs.append(f"Flag-like strings: {', '.join(flag_hits[:5])}")
    if magic_desc and not is_url(target):
        ext = Path(target).suffix.lower()
        if ext and magic_desc and ext.strip('.') not in magic_desc.lower():
            obs.append(f"File type mismatch? extension '{ext}' vs magic '{magic_desc}'")
    interesting = []
    keywords = ["flag", "password", "secret", "key", "todo", "comment"]
    for tool, res in outputs.items():
        text = res.get("stdout", "")
        for line in text.splitlines():
            if any(k in line.lower() for k in keywords):
                interesting.append(line.strip())
                if len(interesting) >= 5:
                    break
        if len(interesting) >= 5:
            break
    if interesting:
        obs.append("Interesting lines: " + "; ".join(interesting))
    if not obs:
        obs.append("No immediate red flags; continue manual analysis.")
    return obs


def suggested_next_steps(category: str) -> List[str]:
    if category == "web":
        return [
            "Enumerate parameters and run dir brute-force (ffuf, gobuster)",
            "Check for default creds / admin panels",
            "Review cookies, headers, and response codes",
            "Look for SSTI/LFI/RFI vectors and reflected inputs",
            "Capture traffic with browser devtools for hidden endpoints",
        ]
    if category == "crypto":
        return [
            "Inspect for PEM/DER headers and key parameters",
            "Test for simple encodings (base64/hex/rot)",
            "Check for common RSA weaknesses (small e, reused primes)",
            "Identify block/stream cipher modes from structure",
            "Search for known-plaintext or crib opportunities",
        ]
    if category in {"pwn", "rev", "reversing", "binary"}:
        return [
            "Load binary in Ghidra/radare2; map entry points",
            "Check protections (NX/PIE/Canary/RELRO) and input paths",
            "Hunt for format strings, buffers, and argv/env parsing",
            "Emulate or run under debugger with controlled input",
            "Extract and analyze strings and hardcoded secrets",
        ]
    if category == "forensics":
        return [
            "Carve files from images/pcaps; inspect extracted artifacts",
            "Run steg tools (zsteg, steghide, stegseek) on media",
            "Timeline and metadata review for hidden hints",
            "Inspect network flows for creds/flags/http objects",
            "Check archives for hidden or nested files",
        ]
    return [
        "Review recon outputs for obvious flags",
        "Try category-specific tools based on file type",
        "Consider entropy/structure anomalies for embedding",
        "Iteratively refine with manual inspection",
        "Provide outputs to an LLM for targeted suggestions",
    ]


def build_llm_prompt(summary: List[str]) -> str:
    joined = " ".join(summary)[:800]
    return (
        "I am solving a CTF challenge. Here is my recon data: "
        f"{joined}. What attack vectors should I try first?"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF recon pipeline")
    parser.add_argument("target", help="File path or URL")
    parser.add_argument("--category", choices=["crypto", "pwn", "web", "forensics", "rev", "misc"], help="Category hint")
    parser.add_argument("--json", dest="json_out", action="store_true", help="Also write JSON report")
    args = parser.parse_args()

    target = args.target
    url_mode = is_url(target)
    if not url_mode and not Path(target).is_file():
        print(f"[!] Target not found: {target}")
        sys.exit(1)

    magic_desc = guess_magic(target)
    category = detect_category(target, args.category, magic_desc)

    cmds = gather_commands(category, target, url_mode)
    cmds = select_commands_with_llm(category, target, cmds)

    print(f"[*] Target: {target}")
    print(f"[*] Category: {category}")
    if magic_desc:
        print(f"[*] Magic: {magic_desc}")

    outputs: Dict[str, Dict[str, str]] = {}
    for name, cmd, timeout in cmds:
        print(f"[+] Running {name}: {cmd}")
        res = run_command(cmd, timeout=timeout)
        outputs[name] = {"command": cmd if isinstance(cmd, str) else " ".join(cmd), **res}

    flag_hits = flag_like_strings(outputs)
    observations = build_observations(target, magic_desc, outputs, flag_hits)

    target_name = target if url_mode else Path(target).name
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    sha = "N/A"
    if not url_mode:
        try:
            sha = sha256sum(Path(target))
        except Exception:
            sha = "unavailable"

    report_name = f"report_{Path(target_name).stem}.md"
    report_path = Path(report_name)

    def format_tool_output(name: str, res: Dict[str, str]) -> str:
        if res.get("status") == "tool not found":
            return f"### {name}\n_tool not found_\n"
        if res.get("status") == "timed out":
            return f"### {name}\n_timed out after {COMMAND_TIMEOUT}s_\n"
        stdout = res.get("stdout", "")
        stderr = res.get("stderr", "")
        combined = stdout if stdout else ""
        if stderr:
            combined += ("\n[stderr]\n" + stderr)
        combined = combined.strip()
        combined = truncate_output(combined)
        status = res.get("status", "")
        return f"### {name}\nStatus: {status}\n\n```\n{combined}\n```\n"

    md_parts: List[str] = []
    md_parts.append(f"# CTF Recon Report — {target_name}")
    md_parts.append(f"**Date:** {ts}")
    md_parts.append(f"**Category:** {category}")
    md_parts.append(f"**File:** {target}")
    md_parts.append(f"**Hash:** {sha}")
    md_parts.append("\n## Quick Observations")
    for obs in observations:
        md_parts.append(f"- {obs}")
    md_parts.append("\n## Tool Outputs")
    for name, res in outputs.items():
        md_parts.append(format_tool_output(name, res))
    md_parts.append("\n## Suggested Next Steps")
    for step in suggested_next_steps(category)[:5]:
        md_parts.append(f"- {step}")
    prompt = build_llm_prompt(observations)
    md_parts.append("\n## LLM Prompt")
    md_parts.append(textwrap.dedent(f"""
    ```
    {prompt}
    ```
    """))

    report_path.write_text("\n".join(md_parts), encoding="utf-8")
    print(f"[+] Markdown report written to {report_path}")

    if args.json_out:
        json_path = report_path.with_suffix(".json")
        payload = {
            "target": target,
            "category": category,
            "timestamp": ts,
            "hash": sha,
            "observations": observations,
            "flag_like": flag_hits,
            "magic": magic_desc,
            "tools": outputs,
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[+] JSON report written to {json_path}")


if __name__ == "__main__":
    main()
