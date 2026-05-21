# Copilot Instructions

This repository contains a Python command-line tool for CTF reconnaissance.

- Keep changes focused on `ctf_recon.py`, tests, documentation, and packaging metadata unless a broader refactor is requested.
- Preserve safe defaults: do not execute untrusted challenge binaries unless the user explicitly passes `--allow-execution`.
- Treat all recon commands as potentially noisy or unavailable on non-Kali systems. Missing tools should degrade gracefully.
- Do not log, print, commit, or persist API keys. NVIDIA NIM support must read `NVIDIA_API_KEY` from the environment.
- Prefer tests that mock external tools instead of requiring `file`, `strings`, `binwalk`, `tshark`, or network access.
- Keep README examples copy-pasteable from the repository root and from the package directory.
