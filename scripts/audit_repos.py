#!/usr/bin/env python3
"""Audit GitHub security settings across all public repos."""

import argparse
import json
import os
import subprocess
import sys

# Fix Windows encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")


def gh_api(endpoint: str) -> any:
    result = subprocess.run(
        ["gh", "api", endpoint, "--paginate"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error: {result.stderr.strip()}", file=sys.stderr)
        return None
    return json.loads(result.stdout)


def get_public_repos(user: str) -> list[dict]:
    repos = gh_api(f"/users/{user}/repos?type=owner&per_page=100")
    if not repos:
        return []
    return [r for r in repos if not r["private"] and not r["fork"]]


def get_security_settings(repo_full_name: str) -> dict:
    data = gh_api(f"/repos/{repo_full_name}")
    if not data:
        return {}
    sa = data.get("security_and_analysis", {})
    return {
        "secret_scanning": sa.get("secret_scanning", {}).get("status") == "enabled",
        "push_protection": sa.get("secret_scanning_push_protection", {}).get("status") == "enabled",
        "non_provider": sa.get("secret_scanning_non_provider_patterns", {}).get("status") == "enabled",
        "dependabot_updates": sa.get("dependabot_security_updates", {}).get("status") == "enabled",
    }


def check_dependabot_alerts(repo_full_name: str) -> bool:
    result = subprocess.run(
        ["gh", "api", f"/repos/{repo_full_name}/vulnerability-alerts",
         "--include", "--silent"],
        capture_output=True, text=True
    )
    return result.returncode == 0 and "204" not in result.stderr


def main():
    parser = argparse.ArgumentParser(description="Audit GitHub repo security settings")
    parser.add_argument("--user", required=True, help="GitHub username")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    repos = get_public_repos(args.user)
    if not repos:
        print("No public repos found.")
        return

    results = []
    for repo in sorted(repos, key=lambda r: r["full_name"]):
        name = repo["full_name"]
        settings = get_security_settings(name)
        results.append({"repo": name, **settings})

    if args.json:
        print(json.dumps(results, indent=2))
        return

    # Pretty table
    check = "\u2705"
    cross = "\u274c"
    print(f"{'Repo':<45} {'Secrets':>8} {'Push':>6} {'Generic':>8} {'Depbot':>7}")
    print("-" * 80)
    for r in results:
        print(
            f"{r['repo']:<45} "
            f"{check if r.get('secret_scanning') else cross:>8} "
            f"{check if r.get('push_protection') else cross:>6} "
            f"{check if r.get('non_provider') else cross:>8} "
            f"{check if r.get('dependabot_updates') else cross:>7}"
        )

    # Summary
    total = len(results)
    fully_protected = sum(
        1 for r in results
        if all(r.get(k) for k in ["secret_scanning", "push_protection", "non_provider"])
    )
    print(f"\n{fully_protected}/{total} repos fully protected")


if __name__ == "__main__":
    main()
