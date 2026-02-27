---
name: github-security
description: "Audit and harden GitHub repository security settings. Use when: (1) enabling secret scanning, push protection, or Dependabot on repos, (2) auditing repos for leaked secrets or exposed credentials, (3) setting up pre-commit hooks for secret/IP/password detection, (4) bulk-configuring security across all public repos, (5) checking for leaked private IPs, API keys, passwords, or personal data in repo history, (6) setting up code scanning or security policies."
---

# GitHub Security Skill

Audit and enforce security settings across GitHub repositories using `gh` CLI.

## Prerequisites

- `gh` CLI authenticated (`gh auth status`)
- Repo admin access for security setting changes

## Workflows

### 1. Audit all public repos

Scan security settings across all non-fork public repos:

```bash
python scripts/audit_repos.py --user <username>
```

Checks per repo: secret_scanning, push_protection, non_provider_patterns, dependabot_alerts, dependabot_updates.

Output: table of repos with ✅/❌ per feature.

### 2. Harden repos

Enable all security features on repos:

```bash
python scripts/harden_repos.py --user <username> [--repos repo1,repo2] [--dry-run]
```

Enables: secret_scanning, secret_scanning_push_protection, secret_scanning_non_provider_patterns, vulnerability_alerts (Dependabot).

Without `--repos`, applies to ALL public non-fork repos. Always confirm with user before bulk changes.

### 3. Scan repo history for secrets

Check if secrets already exist in git history:

```bash
python scripts/scan_history.py --repo <owner/repo> [--since 30d]
```

Uses `gh api` secret scanning alerts endpoint. For deeper scanning, suggests `trufflehog` or `gitleaks`.

### 4. Setup pre-commit hooks

Generate `.pre-commit-config.yaml` with secret detection hooks:

```bash
python scripts/setup_precommit.py --repo-path <path> [--private-ip-check] [--password-check]
```

Hooks included:
- `detect-private-key` (pre-commit-hooks)
- `detect-secrets` (Yelp)
- Custom: private IP detection (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`)
- Custom: password/API key pattern detection

### 5. Check for secret scanning alerts

```bash
python scripts/check_alerts.py --user <username>
```

Lists active secret scanning alerts across all repos with severity and status.

## Manual gh commands (quick reference)

```bash
# Check repo security settings
gh api /repos/OWNER/REPO --jq '.security_and_analysis'

# Enable push protection on a repo
gh api --method PATCH /repos/OWNER/REPO -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

# List secret scanning alerts
gh api /repos/OWNER/REPO/secret-scanning/alerts --jq '.[].secret_type'

# Enable Dependabot alerts
gh api --method PUT /repos/OWNER/REPO/vulnerability-alerts

# List Dependabot alerts
gh api /repos/OWNER/REPO/dependabot/alerts --jq '.[] | "\(.state) \(.security_advisory.summary)"'
```

## Security features reference

See `references/features.md` for details on each GitHub security feature and what it catches.
