# Security Policy

## Supported Versions

Security updates are applied to the latest `main` branch.

## Reporting a Vulnerability

Please report vulnerabilities privately through GitHub Security Advisories if available, or open an issue with minimal reproduction details that do not expose secrets, live targets, or third-party systems.

Include:

- affected version or commit
- operating system and Python version
- exact command used, with secrets redacted
- expected and actual behavior

## Safe Usage

CTF Recon runs local security tools such as `strings`, `file`, `curl`, `binwalk`, and `tshark` when they are available. Treat all challenge files as untrusted.

- Run the tool inside an isolated VM or container for unknown files.
- Keep API keys in environment variables only.
- Review generated reports before sharing them because outputs can contain challenge secrets or credentials.
- Dynamic tracing that executes local binaries is disabled by default. Use `--allow-execution` only in a sandbox.
- Only scan systems and services that you own or have permission to test.
