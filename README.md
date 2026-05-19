# REKOS

REKOS is a terminal-native passive OSINT CLI for local-first public-source investigation workspaces. It helps organize targets, evidence, source outputs, entities, relationships, normalized findings, and correlation-quality scores in a SQLite-backed case folder.

REKOS is designed for passive public-source workflows:

- Public-source investigation workspace
- Target and evidence organizer
- Username, profile, domain, URL, and indicator correlation tool
- Local-first OSINT case workspace
- No login automation, bypass, credential collection, or active exploitation

Cases are stored under `~/rekos_cases/<case_name>` by default. Each case keeps its own SQLite database and export artifacts.

## Installation

Install from a local checkout with `pipx`:

```bash
git clone <repo-url>
cd rekos
pipx install .
rekos --help
```

For development, use an editable install:

```bash
git clone <repo-url>
cd rekos
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
rekos --help
```

Optional external tools:

- `sherlock` for `sherlock_username`
- `maigret` is supported by the investigation engine when installed
- `exiftool` or `mediainfo` for file metadata collection
- Playwright is optional for URL screenshots; HTTP snapshots still work without it

## Quick Start

Create a case:

```bash
rekos new-case acme-osint
```

Investigate a username:

```bash
rekos investigate username acme-osint alice.example
```

Investigate a domain:

```bash
rekos investigate domain acme-osint example.com
```

Capture a public URL snapshot:

```bash
rekos snapshot-url acme-osint https://example.com/profile/alice
```

Review normalized findings:

```bash
rekos findings acme-osint
```

Score finding correlation quality:

```bash
rekos score acme-osint
```

Search local case data:

```bash
rekos search acme-osint example.com
rekos search acme-osint example.com --type finding --source wayback_url --confidence medium
```

Summarize the entity graph:

```bash
rekos graph-summary acme-osint
```

Export the case:

```bash
rekos export-case acme-osint --output ./acme-osint.zip
```

## Supported Sources

| Source | Target types | Dependencies | Notes |
| --- | --- | --- | --- |
| `sherlock_username` | `username` | `sherlock` binary | Runs Sherlock with safe subprocess arguments and parses public profile URLs. |
| `http_snapshot` | `url` | none | Captures public HTTP response artifacts and optional Playwright screenshot. |
| `rdap_domain` | `domain` | none | Uses public HTTPS RDAP lookup and stores raw JSON output. |
| `crtsh_domain` | `domain` | none | Queries the public crt.sh certificate transparency endpoint. |
| `wayback_url` | `url`, `domain` | none | Queries public Wayback CDX data and records archive URLs. |

Source utilities:

```bash
rekos sources list
rekos sources check
rekos sources run acme-osint rdap_domain example.com
```

## Core Commands

```bash
rekos add-entity acme-osint --type domain --value example.com
rekos relate-entities acme-osint --from <entity_uuid> --to <entity_uuid> --type related_to --confidence medium
rekos list-targets acme-osint
rekos list-sources acme-osint
rekos show-investigation acme-osint
rekos report acme-osint --format md
```

## Safety And Ethics

REKOS is passive-only OSINT tooling. Use it only for lawful, authorized, and ethical public-source research.

REKOS must not be used for:

- Logging into accounts or automating authenticated sessions
- Bypassing access controls, paywalls, CAPTCHAs, bot protection, or rate limits
- Credential collection, phishing, account abuse, or social engineering
- Exploitation, destructive operations, or aggressive crawling
- Claiming identity ownership from correlation results

Scores are correlation-quality indicators only. A high score means stronger local correlation support, not proof of identity, ownership, compromise, or intent.

## Local Data Model

REKOS stores:

- Case metadata in SQLite
- Targets, entities, relationships, notes, timeline events
- Raw source outputs under `exports/`
- Evidence and snapshot artifacts
- Normalized findings with correlation-quality scores
- Case ZIP exports with manifest data

## Development

```bash
python -m pip install -e ".[dev]"
pytest
rekos --help
```

Before submitting a change:

```bash
pytest
python -m compileall rekos
git diff --check
```

## Roadmap

- More passive source adapters with explicit safety boundaries
- Stronger report templates and case export validation
- Improved graph summaries and finding explainability
- Better import/export interoperability
- Optional UI views while keeping the CLI and local-first storage as the core

## License

MIT License. See [LICENSE](LICENSE).
