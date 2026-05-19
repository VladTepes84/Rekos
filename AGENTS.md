# AGENTS.md

## Project

REKOS is a terminal-native passive OSINT CLI and public-source investigation workspace.

It is a local-first OSINT case workspace, target and evidence organizer, and username/profile/indicator correlation tool.

REKOS is not a hacking, phishing, credential collection, bypass, exploitation, stalking, or doxxing tool.

## Working Rules

- Keep changes minimal, local, and reversible.
- Keep the code modular and typed.
- Prefer local storage under `~/rekos_cases/<case_name>`.
- Store case state in SQLite inside each case folder.
- Use Rich for terminal output.
- Add pytest tests for functional behavior.
- Keep all collection passive and public-source only.
- Do not implement scraping behind authentication, bypass, phishing, credential collection, account abuse, stalking automation, doxxing automation, or aggressive automation.
- Reports and outputs must distinguish facts, correlations, and unverified hypotheses.
