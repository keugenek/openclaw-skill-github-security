#!/usr/bin/env python3
"""Check secret scanning and Dependabot alerts across repos."""

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


def gh_api(endpoint: str) -> any:
    result = subprocess.run(
        ["gh", "api", endpoint], capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def get_public_repos(user: str) -> list[str]:
    result = subprocess.run(
        ["gh", "api", f"/users/{user}/repos?type=owner&per_page=100", "--paginate",
         "--jq", '.[] | select(.private == false and .fork == false) | .full_name'],
        capture_output=True, text=True
    )
    return [r.strip() for r in result.stdout.strip().split("\n") if r.strip()]


def check_secret_alerts(repo: str) -> list[dict]:
    alerts = gh_api(f"/repos/{repo}/secret-scanning/alerts?state=open")
    if not alerts or not isinstance(alerts, list):
        return []
    return [
        {
            "type": a.get("secret_type_display_name", a.get("secret_type", "unknown")),
            "created": a.get("created_at", "")[:10],
            "url": a.get("html_url", ""),
        }
        for a in alerts
    ]


def check_dependabot_alerts(repo: str) -> list[dict]:
    alerts = gh_api(f"/repos/{repo}/dependabot/alerts?state=open")
    if not alerts or not isinstance(alerts, list):
        return []
    return [
        {
            "severity": a.get("security_advisory", {}).get("severity", "unknown"),
            "summary": a.get("security_advisory", {}).get("summary", "")[:80],
            "package": a.get("dependency", {}).get("package", {}).get("name", ""),
        }
        for a in alerts
    ]


def main():
    parser = argparse.ArgumentParser(description="Check security alerts across repos")
    parser.add_argument("--user", required=True, help="GitHub username")
    parser.add_argument("--type", choices=["secrets", "dependabot", "all"], default="all")
    args = parser.parse_args()

    repos = get_public_repos(args.user)
    if not repos:
        print("No repos found.")
        return

    total_secrets = 0
    total_deps = 0

    for repo in sorted(repos):
        alerts_found = False

        if args.type in ("secrets", "all"):
            secrets = check_secret_alerts(repo)
            if secrets:
                alerts_found = True
                total_secrets += len(secrets)
                print(f"\n\u26a0\ufe0f  {repo} — {len(secrets)} secret alert(s):")
                for s in secrets:
                    print(f"    {s['type']} (found {s['created']})")

        if args.type in ("dependabot", "all"):
            deps = check_dependabot_alerts(repo)
            if deps:
                alerts_found = True
                total_deps += len(deps)
                print(f"\n\u26a0\ufe0f  {repo} — {len(deps)} dependency alert(s):")
                for d in deps:
                    print(f"    [{d['severity']}] {d['package']}: {d['summary']}")

    print(f"\n--- Summary ---")
    print(f"Repos scanned: {len(repos)}")
    if args.type in ("secrets", "all"):
        print(f"Open secret alerts: {total_secrets}")
    if args.type in ("dependabot", "all"):
        print(f"Open dependency alerts: {total_deps}")

    if total_secrets == 0 and total_deps == 0:
        print("\u2705 No open alerts found.")


if __name__ == "__main__":
    main()
