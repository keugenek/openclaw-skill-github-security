# GitHub Security Features Reference

## Secret Scanning
Scans repo content for known secret patterns from 200+ providers (AWS keys, GCP tokens, Stripe keys, etc).
- Free for public repos
- API: `security_and_analysis.secret_scanning`

## Push Protection
Blocks pushes containing detected secrets BEFORE they enter git history.
- Prevents the hardest-to-fix leak scenario (secret in history)
- API: `security_and_analysis.secret_scanning_push_protection`

## Non-Provider Patterns
Detects generic secrets not tied to a specific provider:
- Private keys (RSA, SSH, PGP)
- Generic passwords in code (`password = "..."`)
- HTTP basic auth in URLs
- API: `security_and_analysis.secret_scanning_non_provider_patterns`

## Dependabot Alerts
Monitors dependencies for known CVEs. Auto-creates alerts when vulnerabilities found.
- API: PUT `/repos/OWNER/REPO/vulnerability-alerts`

## Dependabot Security Updates
Auto-creates PRs to update vulnerable dependencies.
- API: `security_and_analysis.dependabot_security_updates`

## Code Scanning (Advanced Security)
SAST analysis via CodeQL or third-party tools. Requires GitHub Actions workflow.
- Free for public repos
- Setup: `.github/workflows/codeql.yml`

## What each feature catches

| Threat | Secret Scanning | Push Protection | Non-Provider | Dependabot | Pre-commit |
|--------|:-:|:-:|:-:|:-:|:-:|
| AWS/GCP/Azure keys | ✅ | ✅ | | | ✅ |
| Generic passwords | | | ✅ | | ✅ |
| Private SSH/PGP keys | | | ✅ | | ✅ |
| Private IPs in code | | | | | ✅ (custom) |
| MAC addresses | | | | | ✅ (custom) |
| Vulnerable deps | | | | ✅ | |
| SQL injection | | | | | | CodeQL |
