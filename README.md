# REKOS

REKOS is a local defensive case-management CLI for cybersecurity investigations.

```bash
rekos new-case suspicious-login
rekos add-target suspicious-login --type username --value alice@example.com
rekos hash-file suspicious-login ./artifact.bin
rekos add-note suspicious-login "Initial triage note"
rekos report suspicious-login --format md
```

Cases are stored under `~/rekos_cases/<case_name>` by default, with SQLite state inside each case folder.

