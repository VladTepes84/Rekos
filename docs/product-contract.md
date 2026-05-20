# REKOS Product/UX Contract

## Purpose

REKOS is a terminal-native passive OSINT CLI and local-first public-source investigation workspace.

This contract protects the public user experience while REKOS grows through separate modules, richer reports, and stronger exports.

The guiding rule is:

> REKOS must become more powerful in modules and reports, not noisier in the terminal.

## Permanent UX Rules

- `rekos quickstart` must remain stable unless a change is explicitly scoped as a product/UX contract revision.
- The cinematic banner, visual identity, and base REKOS presentation must remain stable.
- Normal stdout must stay clean, short, and operational.
- Base command output must summarize what happened, not dump raw source details.
- Reports and exports may contain full detail, raw appendix material, evidence tables, timelines, source status, and structured findings.
- Debug and raw source output must be optional, explicit, and separate from normal stdout.
- New modules must add capability without making existing base commands more verbose.
- New source integrations must use timeouts, graceful failure, and per-source error handling.
- Source failures must not crash the whole investigation when other sources can continue.
- Missing optional API keys must skip the related source cleanly and must not break the user flow.
- Every new feature must include acceptance tests that protect the base UX from accidental noise or behavior drift.

## Runtime Boundaries

- REKOS remains passive and public-source only.
- Do not add login automation, authentication bypass, CAPTCHA bypass, credential collection, exploitation, stalking automation, doxxing automation, or aggressive collection.
- Network lookups must be bounded by conservative timeouts and clear source attribution.
- Raw source errors and tool stderr belong in exports or debug output, not normal terminal output.
- CLI warnings should be brief, actionable, and non-destructive.

## Output Model

Normal terminal output:

- completion status;
- small counts;
- short warnings;
- next useful artifact path when relevant.

Reports and exports:

- detailed findings;
- confidence and evidence basis;
- source status;
- timeline;
- graph/export data;
- raw source appendix when useful.

Debug/raw output:

- explicit opt-in only;
- separated from base command output;
- suitable for troubleshooting, not default user reading.

## Module Rule

New capabilities should be added as separate modules, adapters, reports, exports, or explicit commands.

Existing user-facing commands should keep their current visible behavior unless the task explicitly authorizes a UX contract change.

## Official Roadmap

0. Product/UX Contract
1. Username runtime stability invisibile
2. Domain workflow piccolo
3. Report/export v2 parziale
4. URL/IP indicator workflow
5. Email/phishing artifact workflow
6. Graph/export pulito
7. API key manager
8. Preset quick/deep
9. README/release

## Acceptance Standard

A change is acceptable only when:

- existing base UX remains stable;
- normal stdout stays concise;
- raw/debug data is separated;
- optional source/API failures are graceful;
- tests cover the intended feature and protect the base UX;
- passive-only boundaries remain intact.
