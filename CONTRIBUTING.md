# Contributing

Thanks for helping improve CTF Recon.

## Development Setup

```bash
cd ctf-recon
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Quality Checks

Run these before opening a pull request:

```bash
python -m ruff check .
python -m pytest -q
python -m bandit -q -r ctf_recon.py
```

## Guidelines

- Keep recon commands deterministic and category-specific.
- Mock external tools in tests.
- Avoid broad network activity in automated checks.
- Keep unsafe actions behind explicit CLI flags.
- Update the README when adding user-facing flags or behavior.
