# AGENTS.md

## Project
REKOS is a defensive case-management CLI for local cyber investigation notes, targets, file hashes, and reports.

## Working Rules
- Keep changes minimal, local, and reversible.
- Keep the code modular and typed.
- Prefer local storage under `~/rekos_cases/<case_name>`.
- Store case state in SQLite inside each case folder.
- Use Rich for terminal output.
- Add pytest tests for functional behavior.
- Do not implement scraping, bypass, phishing, credential collection, account abuse, or aggressive automation.

