# Changelog

## 1.3.2

- Improved verbose findings output with analyst-readable category grouping, compact reasons, short IDs by default, and optional full UUID display.
- Clarified Python version requirements and recommended pipx installation with Python 3.12.

## 1.3.0

- Added stronger domain investigation enrichment with DNS, RDAP/WHOIS fallback, passive web/TLS checks, provider hints, and crt.sh certificate transparency.
- Added public-target safety validation for URL/domain workflows to reject local, private, reserved, multicast, link-local, and metadata-service targets.
- Improved source-run tracking so `list-sources` shows each source run with per-run counts.
- Made reports more readable by compacting entity, relationship, and finding sections.

## 1.2.0

- Added domain investigation v1 with passive RDAP and DNS record collection.
- Added domain findings, graph entities, and concise CLI summaries for domain workflows.
- Prepared REKOS for single-package PyPI distribution with `pipx install rekos`.

## 1.1.2

- Cleaned quickstart and version display so the banner stays stable and version output is dynamic.
- Kept `rekos version` concise with plain version output.

## 1.1.x

- Improved findings readability with concise default output and detailed `--verbose` mode.
- Improved graph-summary readability and clarified internal relationship counts.

## 1.1.0

- Added UX improvements for findings and graph review workflows.
- Kept detailed technical evidence available through verbose and export paths.

## 1.0.0

- Initial usable public release of REKOS as a terminal-native passive OSINT CLI.
- Included local case workspaces, SQLite storage, evidence registry, timeline, username investigation, source adapters, reports, and exports.
