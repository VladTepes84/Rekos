# Contributing To REKOS

Thanks for considering a contribution. REKOS is a passive OSINT CLI, so changes must preserve local-first storage and passive-only collection boundaries.

## Development Setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
rekos --help
```

## Contribution Guidelines

- Keep changes small, typed, and easy to review.
- Add or update pytest coverage for functional changes.
- Do not add scraping behind authentication, login automation, bypass logic, credential collection, phishing support, exploitation, or aggressive crawling.
- New source adapters must declare dependencies, supported target types, and passive-only behavior.
- Persist source outputs locally and avoid silent failures.
- Treat finding scores as correlation-quality indicators only.

## Before Opening A Pull Request

Run:

```bash
pytest
python -m compileall rekos
git diff --check
```

Include a short summary of behavior changes, tests run, and any remaining limitations.
