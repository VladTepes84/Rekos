# Security Policy

REKOS is passive OSINT tooling. Security reports are welcome when they affect local data integrity, safe command execution, dependency handling, artifact export, or passive collection boundaries.

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting A Vulnerability

Please report vulnerabilities privately through the project's GitHub security advisory workflow when available. If that is not available, open a minimal public issue that does not include exploit details and ask for a private contact path.

Include:

- Affected version or commit
- Operating system and Python version
- Reproduction steps
- Impact
- Suggested fix, if known

## Safety Boundaries

Reports about missing protections are especially useful when they involve:

- Shell invocation or unsafe subprocess handling
- Writing outside the intended case/export paths
- Unsafe ZIP export behavior
- Accidental credential capture
- Authenticated scraping, bypass, CAPTCHA evasion, or aggressive automation
- Finding scores that imply identity ownership rather than correlation quality

REKOS maintainers will not accept features that add credential collection, phishing, bypass, exploitation, or non-passive collection behavior.
