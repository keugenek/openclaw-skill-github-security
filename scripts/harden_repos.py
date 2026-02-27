#!/usr/bin/env python3
"""Enable security features on GitHub repos."""

import argparse
import json
import os
import subprocess
import sys

if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")


def gh_api_patch(endpoint: str, body: dict) -> bool:
    result = subprocess.run(
        ["gh", "api", "--method", "PATCH", endpoint, "--input", "-"],
        input=json.dumps(body), capture_output=True, text=True
    )
    return result.returncode == 0


def gh_api_put(endpoint: str) -> bool:
    result = subprocess.run(
        ["gh", "api", "--method", "PUT", endpoint],
        capture_output=True, text=True
    )
    return result.returncode == 0


def get_public_repos(user: str) -> list[str]:
    result = subprocess.run(
        ["gh", "api", f"/users/{user}/repos?type=owner&per_page=100", "--paginate",
         "--jq", '.[] | select(.private == false and .fork == false) | .full_name'],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []
    return [r.strip() for r in result.stdout.strip().split("\n") if r.strip()]


def harden_repo(repo: str, dry_run: bool = False) -> dict:
    results = {}

    # Security analysis settings
    body = {
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
            "secret_scanning_non_provider_patterns": {"status": "enabled"},
        }
    }

    if dry_run:
        print(f"  [DRY RUN] Would enable secret scanning + push protection + non-provider patterns")
        print(f"  [DRY RUN] Would enable Dependabot vulnerability alerts")
        return {"secret_scanning": True, "dependabot": True}

    ok = gh_api_patch(f"/repos/{repo}", body)
    results["secret_scanning"] = ok
    if ok:
        print(f"  \u2705 Secret scanning + push protection + non-provider patterns")
    else:
        print(f"  \u274c Failed to enable secret scanning settings")

    ok = gh_api_put(f"/repos/{repo}/vulnerability-alerts")
    results["dependabot"] = ok
    if ok:
        print(f"  \u2705 Dependabot vulnerability alerts")
    else:
        print(f"  \u274c Failed to enable Dependabot alerts")

    return results


def main():
    parser = argparse.ArgumentParser(description="Harden GitHub repo security settings")
    parser.add_argument("--user", required=True, help="GitHub username")
    parser.add_argument("--repos", help="Comma-separated repo names (without owner). If omitted, all public repos.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed")
    args = parser.parse_args()

    if args.repos:
        repos = [f"{args.user}/{r.strip()}" for r in args.repos.split(",")]
    else:
        repos = get_public_repos(args.user)

    if not repos:
        print("No repos found.")
        return

    print(f"{'[DRY RUN] ' if args.dry_run else ''}Hardening {len(repos)} repos:\n")

    for repo in sorted(repos):
        print(f"\n{repo}:")
        harden_repo(repo, dry_run=args.dry_run)

    print(f"\n\u2705 Done. {len(repos)} repos processed.")


if __name__ == "__main__":
    main()
