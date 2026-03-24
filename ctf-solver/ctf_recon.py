#!/usr/bin/env python3
"""CTF recon helper.

Runs lightweight recon commands against a challenge file, URL, or host:port
and produces structured Markdown/JSON reports suitable for handoff to a
stronger LLM."""

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


def parse_host_port(target: str) -> Optional[Tuple[str, int]]:
    match = re.match(r"^([a-zA-Z0-9_.-]+):(\d{1,5})$", target)
    if not match:
        return None
    host, port_str = match.groups()
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return host, port
    except ValueError:
        return None
    return None


def sniff_python_category(path: Path) -> Optional[str]:
    """Heuristic: detect crypto/web/pwn intent for Python sources."""
    try:
        data = path.read_text(errors="ignore")
    except Exception:
        return None
    lower = data.lower()
    crypto_keys = ["gmpy2", "pycryptodome", "crypto", "cryptography", "rsa", "ecdsa", "hashlib", "secp", "dh", "diffie"]
    pwn_keys = ["pwntools", "pwn", "socket", "struct", "recv", "send", "exploit"]
    web_keys = ["flask", "django", "fastapi", "requests", "http.server"]
    if any(k in lower for k in crypto_keys):
        return "crypto"
    if any(k in lower for k in pwn_keys):
        return "pwn"
    if any(k in lower for k in web_keys):
        return "web"
    return None


def sha256sum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_category(target: str, provided: Optional[str], magic_desc: Optional[str], net_mode: bool) -> str:
    if provided:
        return provided.lower()
    if net_mode:
        return "pwn"
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

    # Python scripts: peek imports to classify
    if ext == ".py" or (magic_desc and "python script" in magic_desc.lower()):
        hint = sniff_python_category(path)
        if hint:
            return hint
        return "misc"

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


def truncate_lines(text: str, max_lines: int = 100) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join([*lines[:max_lines], "...<truncated>..."])


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


def extract_symbols(outputs: Dict[str, Dict[str, str]]) -> List[str]:
    symbols: List[str] = []
    nm_out = outputs.get("nm", {}).get("stdout", "")
    rabin_out = outputs.get("rabin2_symbols", {}).get("stdout", "")
    for text in (nm_out, rabin_out):
        for line in text.splitlines():
            parts = line.strip().split()
            if parts:
                candidate = parts[-1]
                if candidate and candidate not in symbols:
                    symbols.append(candidate)
    return symbols


def top_lines(text: str, max_lines: int = 10) -> str:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return "\n".join(lines[:max_lines])


def suspicious_strings(outputs: Dict[str, Dict[str, str]]) -> List[str]:
    hits: List[str] = []
    keywords = ["flag", "ctf", "secret", "password", "key"]
    for name in ["strings_grep", "strings_full"]:
        text = outputs.get(name, {}).get("stdout", "")
        for line in text.splitlines():
            lower = line.lower()
            if any(k in lower for k in keywords):
                if line.strip() and line.strip() not in hits:
                    hits.append(line.strip())
            if len(hits) >= 10:
                return hits
    return hits


def call_llm(prompt: str) -> Tuple[Optional[str], str]:
    """Call NVIDIA NIM backend; return (text, status) where status notes failures."""
    api_key = os.getenv("NVIDIA_API_KEY")
    if not api_key:
        return None, "missing_api_key"
    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return None, "missing_openai_sdk"

    model = os.getenv("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct")
    try:
        client = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=api_key)
        completion = client.chat.completions.create(
            model=model,
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
        return "".join(chunks), "ok"
    except Exception:
        return None, "error"


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
    raw, _status = call_llm("\n".join(prompt_lines))
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


def gather_commands(category: str, target: str, is_url_target: bool, net_mode: bool, host_port: Optional[Tuple[str, int]], magic_desc: Optional[str]) -> List[Tuple[str, Sequence[str] | str, int]]:
    cmds: List[Tuple[str, Sequence[str] | str, int]] = []

    if net_mode and host_port:
        host, port = host_port
        cmds.extend([
            ("nc_banner", f"nc -w 5 {shlex.quote(host)} {port}", COMMAND_TIMEOUT),
            ("nc_empty", f"timeout 10 nc {shlex.quote(host)} {port} < /dev/null", COMMAND_TIMEOUT),
        ])
        return cmds

    always_file_cmds: List[Tuple[str, str]] = [
        ("file", f"file {shlex.quote(target)}"),
        ("strings_grep", f"strings {shlex.quote(target)} | grep -i 'flag\\|ctf\\|key\\|password\\|secret'"),
        ("xxd_head", f"xxd {shlex.quote(target)} | head -40"),
        ("sha256sum", f"sha256sum {shlex.quote(target)}"),
        ("exiftool", f"exiftool {shlex.quote(target)}"),
    ]

    # If small script/text file, include full source with cat
    try:
        file_size = Path(target).stat().st_size
    except Exception:
        file_size = 0
    is_text_like = magic_desc is not None and "text" in magic_desc.lower()
    is_script = magic_desc is not None and ("python script" in magic_desc.lower() or target.endswith(".py"))
    if file_size > 0 and file_size <= 5 * 1024 and (is_text_like or is_script):
        always_file_cmds.insert(1, ("source_full", f"cat {shlex.quote(target)}"))
    elif file_size > 0 and is_text_like:
        always_file_cmds.insert(1, ("source_head", f"sed -n '1,200p' {shlex.quote(target)}"))

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
        if target.lower().endswith((".pcap", ".pcapng")):
            cmds.extend(
                [
                    ("tshark_summary", ["tshark", "-r", target, "-q", "-z", "io,phs"], COMMAND_TIMEOUT),
                    ("tshark_http_uris", ["tshark", "-r", target, "-Y", "http", "-T", "fields", "-e", "http.request.uri"], COMMAND_TIMEOUT),
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


def build_observations(target: str, magic_desc: Optional[str], outputs: Dict[str, Dict[str, str]], flag_hits: List[str]) -> List[str]:
    obs: List[str] = []
    if flag_hits:
        obs.append(f"Flag-like strings: {', '.join(flag_hits[:5])}")
    if magic_desc and Path(target).exists():
        ext = Path(target).suffix.lower()
        if ext and magic_desc and ext.strip('.') not in magic_desc.lower():
            obs.append(f"File type mismatch? extension '{ext}' vs magic '{magic_desc}'")
    interesting = []
    keywords = ["flag", "password", "secret", "key", "todo", "comment"]
    for _tool, res in outputs.items():
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


def build_llm_prompt_deep(
    category: str,
    target: str,
    magic_desc: Optional[str],
    sha: str,
    observations: List[str],
    outputs: Dict[str, Dict[str, str]],
    challenge_title: Optional[str] = None,
    challenge_description: Optional[str] = None,
) -> str:
    """Build rich prompt with all non-empty recon outputs; limit length."""

    def section_if_ok(name: str, key: str, max_lines: int = 100) -> Optional[str]:
        res = outputs.get(key, {})
        if res.get("status") != "ok":
            return None
        body = res.get("stdout", "").strip()
        if not body:
            return None
        return f"[{name}]\n{truncate_lines(body, max_lines)}"

    sections: List[str] = []
    header = [
        f"Category: {category}",
        f"Target: {target}",
        f"Type: {'URL' if is_url(target) else 'file'}",
    ]
    if challenge_title:
        header.append(f"Challenge: {challenge_title}")
    if challenge_description:
        header.append(f"Description: {challenge_description[:400]}")
    if magic_desc:
        header.append(f"Magic: {magic_desc}")
    if sha and sha != "N/A":
        header.append(f"SHA256: {sha}")
    if observations:
        header.append("Observations: " + "; ".join(observations[:5]))
    sections.append(" | ".join(header))

    # Prefer full source if available
    if "source_full" in outputs and outputs["source_full"].get("status") == "ok":
        full = outputs["source_full"].get("stdout", "").strip()
        if full:
            sections.append("[full_source]\n" + full)
    else:
        for name, key in [
            ("file", "file"),
            ("checksec", "checksec"),
            ("readelf", "readelf"),
            ("objdump", "objdump"),
            ("nm", "nm"),
            ("rabin2_symbols", "rabin2_symbols"),
            ("strings", "strings_full"),
            ("strings_grep", "strings_grep"),
            ("binwalk", "binwalk"),
            ("exiftool", "exiftool"),
            ("strace", "strace"),
            ("ltrace", "ltrace"),
            ("rabin2_info", "rabin2_info"),
        ]:
            sec = section_if_ok(name, key)
            if sec:
                sections.append(sec)
    # Add network service output if present
    net_outputs = []
    for key in ["nc_banner", "nc_empty"]:
        res = outputs.get(key, {})
        if res.get("status") == "ok" and res.get("stdout"):
            net_outputs.append(f"[{key}]\n" + truncate_lines(res["stdout"], 100))
    if net_outputs:
        sections.append("[Network Service Output]\n" + "\n---\n".join(net_outputs))

    web_parts: List[str] = []
    for key in ["curl_head", "curl_headers", "curl_grep", "whatweb", "robots", "git_head"]:
        res = outputs.get(key, {})
        if res.get("status") == "ok" and res.get("stdout"):
            web_parts.append(truncate_lines(res["stdout"], 100))
    if web_parts:
        sections.append("[web]\n" + "\n---\n".join(web_parts))

    for key in ["tshark_summary", "tshark_http_uris", "tshark_follow"]:
        res = outputs.get(key, {})
        if res.get("status") == "ok" and res.get("stdout"):
            sections.append(f"[{key}]\n" + truncate_lines(res["stdout"], 100))

    enc = outputs.get("python_detect_encoding", {})
    if enc.get("status") == "ok" and enc.get("stdout"):
        sections.append("[encoding]\n" + truncate_lines(enc["stdout"], 100))

    instruction = (
        "You are a CTF analyst. Analyze this recon data and extract:\n"
        "NEVER guess or fabricate flag values. If you think you know the flag, say 'FLAG RECOVERY REQUIRES: <tool/method>' instead. Only report what is explicitly present in the recon data.\n"
        "1. VULNERABILITY INDICATORS - any functions, strings, protections, or patterns that suggest a specific vulnerability class\n"
        "2. KEY FINDINGS - the most important observations from the recon (e.g. dangerous functions present, missing protections, hidden functions, suspicious metadata, encoded data detected)\n"
        "3. BINARY PROFILE - summarize the target in one paragraph (architecture, protections, purpose, notable symbols)\n"
        "4. ATTACK SURFACE - list every possible input vector found (argv, stdin, network, files, env vars, format strings etc)\n"
        "5. RECOMMENDED TOOL SEQUENCE - ordered list of next tools to run with exact commands and expected output\n"
        "6. SOLVE HYPOTHESIS - your best guess at the intended solution based purely on the evidence in the recon data\n"
        "Respond with clearly labeled sections 1-6.\n"
    )

    prompt = instruction + "\n" + "\n\n".join(sections)
    return prompt[:12000]


def process_target(target: str, args: argparse.Namespace, challenge_title: Optional[str], challenge_description: Optional[str]) -> Dict[str, Any]:
    url_mode = is_url(target)
    host_port = None if url_mode else parse_host_port(target)
    net_mode = host_port is not None

    if not url_mode and not net_mode and not Path(target).is_file():
        print(f"[!] Target not found: {target}")
        return {}

    magic_desc = None if net_mode or url_mode else guess_magic(target)
    category = detect_category(target, args.category, magic_desc, net_mode)

    cmds = gather_commands(category, target, url_mode, net_mode, host_port, magic_desc)
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

    target_name = target if url_mode or net_mode else Path(target).name
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    sha = "N/A"
    if not url_mode and not net_mode:
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
    md_parts.append(f"**Target:** {target}")
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

    prompt = build_llm_prompt_deep(
        category,
        target,
        magic_desc,
        sha,
        observations,
        outputs,
        challenge_title=challenge_title,
        challenge_description=challenge_description,
    )
    md_parts.append("\n## LLM Prompt (Deep)")
    md_parts.append(textwrap.dedent(f"""
    ```
    {prompt}
    ```
    """))

    llm_text, llm_status = call_llm(prompt)
    md_parts.append("\n## Deep Analysis")
    if llm_text:
        md_parts.append("Status: ok\n")
        md_parts.append(textwrap.dedent(f"""
        {llm_text.strip()}
        """))
    else:
        reason = {
            "missing_api_key": "NVIDIA_API_KEY missing",
            "missing_openai_sdk": "openai package not installed",
        }.get(llm_status, "LLM call failed")
        md_parts.append(f"Status: failed ({reason})")

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
            "llm_status": llm_status,
            "llm_text": llm_text or "",
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[+] JSON report written to {json_path}")

    return {
        "target": target,
        "target_name": target_name,
        "category": category,
        "magic": magic_desc,
        "sha": sha,
        "observations": observations,
        "flag_hits": flag_hits,
        "outputs": outputs,
        "llm_status": llm_status,
        "llm_text": llm_text or "",
        "report_path": str(report_path),
        "prompt": prompt,
    }


def run_combined_analysis(results: List[Dict[str, Any]], challenge_title: Optional[str], challenge_description: Optional[str]) -> None:
    if not results:
        return

    def snippet(outputs: Dict[str, Dict[str, str]], key: str, max_lines: int = 40) -> Optional[str]:
        res = outputs.get(key, {})
        if res.get("status") == "ok" and res.get("stdout"):
            return truncate_lines(res["stdout"], max_lines)
        return None

    sections: List[str] = []
    header = ["Cross-target correlation for challenge"]
    if challenge_title:
        header.append(f"Title: {challenge_title}")
    if challenge_description:
        header.append(f"Description: {challenge_description[:400]}")
    sections.append(" | ".join(header))

    for item in results:
        block: List[str] = []
        block.append(f"Target: {item.get('target_name')} (category {item.get('category')})")
        if item.get("magic"):
            block.append(f"Magic: {item['magic']}")
        if item.get("sha"):
            block.append(f"SHA: {item['sha']}")
        obs = item.get("observations", [])
        if obs:
            block.append("Observations: " + "; ".join(obs[:3]))

        outputs = item.get("outputs", {})
        for key in ["source_head", "strings_grep", "xxd_head"]:
            sn = snippet(outputs, key)
            if sn:
                block.append(f"[{key}]\n{sn}")
        combined = "\n".join(block)
        sections.append(combined)

    instruction = (
        "You are a CTF analyst. You have multiple related files from the same challenge. "
        "Identify relationships between them (e.g., generator/output pairs, shared parameters, encoding). "
        "Propose a single unified solve path that uses the files together. "
        "Highlight which file produces data consumed by another and how to recover the flag."
    )
    prompt = instruction + "\n\n" + "\n\n---\n\n".join(sections)
    prompt = prompt[:12000]

    llm_text, llm_status = call_llm(prompt)
    report_name = "report_combined.md"
    report_path = Path(report_name)

    md_parts: List[str] = []
    md_parts.append("# Combined Recon Report")
    if challenge_title:
        md_parts.append(f"**Title:** {challenge_title}")
    if challenge_description:
        md_parts.append(f"**Description:** {challenge_description}")
    md_parts.append("\n## Summary of Inputs")
    md_parts.extend(["- " + sec.replace("\n", " | ") for sec in sections[1:]])
    md_parts.append("\n## Combined LLM Prompt")
    md_parts.append("```\n" + prompt + "\n```")
    md_parts.append("\n## Combined Analysis")
    if llm_text:
        md_parts.append("Status: ok\n\n" + llm_text.strip())
    else:
        reason = {
            "missing_api_key": "NVIDIA_API_KEY missing",
            "missing_openai_sdk": "openai package not installed",
        }.get(llm_status, "LLM call failed")
        md_parts.append(f"Status: failed ({reason})")

    report_path.write_text("\n".join(md_parts), encoding="utf-8")
    print(f"[+] Combined report written to {report_path}")


def main():
    parser = argparse.ArgumentParser(description="CTF recon pipeline")
    parser.add_argument("targets", nargs="+", help="File paths, URLs, or host:port targets")
    parser.add_argument("--title", help="Challenge title", dest="challenge_title")
    parser.add_argument("--description", help="Challenge description", dest="challenge_description")
    parser.add_argument("--category", choices=["crypto", "pwn", "web", "forensics", "rev", "misc"], help="Category hint")
    parser.add_argument("--json", dest="json_out", action="store_true", help="Also write JSON report")
    args = parser.parse_args()

    results: List[Dict[str, Any]] = []
    for tgt in args.targets:
        res = process_target(tgt, args, args.challenge_title, args.challenge_description)
        if res:
            results.append(res)

    if len(results) > 1:
        run_combined_analysis(results, args.challenge_title, args.challenge_description)

if __name__ == "__main__":
    main()
