# REKOS

REKOS is a terminal-native passive OSINT CLI and public-source investigation workspace.

It provides a local-first OSINT case workspace for organizing targets and evidence, correlating usernames/profiles/indicators, hashing files, recording notes, building timelines, running passive username checks, extracting metadata from user-provided files, validating cases, and exporting portable archives.

REKOS is designed for lawful passive OSINT workflows. It is not a hacking, phishing, credential collection, bypass, exploitation, stalking, or doxxing tool.

## Example

```bash
rekos new-case public-profile-review
rekos add-target public-profile-review --type username --value example_user
rekos hash-file public-profile-review ./public_artifact.png
rekos add-note public-profile-review "Public profile observed with matching username pattern."
rekos report public-profile-review --format md
