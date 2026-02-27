#!/usr/bin/env python3
"""Generate .pre-commit-config.yaml with security hooks."""

import argparse
import os

TEMPLATE = """repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=500']

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
"""

IP_HOOK = """
  - repo: local
    hooks:
      - id: no-private-ips
        name: Block private IPs
        entry: python -c "
import re, sys
patterns = [r'192\\\\.168\\\\.\\\\d+\\\\.\\\\d+', r'10\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+', r'172\\\\.(1[6-9]|2\\\\d|3[01])\\\\.\\\\d+\\\\.\\\\d+']
ok = True
for f in sys.argv[1:]:
    try:
        for i, line in enumerate(open(f, encoding='utf-8', errors='ignore'), 1):
            if any(re.search(p, line) for p in patterns):
                if 'example' not in line.lower() and '10.0.0.' not in line:
                    print(f'{f}:{i}: Private IP: {line.strip()[:80]}'); ok = False
    except: pass
sys.exit(0 if ok else 1)
"
        language: python
        types: [text]
        exclude: '(\\.secrets\\.baseline|cluster\\.yaml)$'
"""

PASSWORD_HOOK = """
      - id: no-passwords
        name: Block password patterns
        entry: python -c "
import re, sys
patterns = [r'(?i)(password|passwd|pwd)\\\\s*[:=]\\\\s*[\\\"\\'].+[\\\"\\']', r'(?i)(api[_-]?key|token|secret)\\\\s*[:=]\\\\s*[\\\"\\'][a-zA-Z0-9]{16,}[\\\"\\']']
ok = True
for f in sys.argv[1:]:
    try:
        for i, line in enumerate(open(f, encoding='utf-8', errors='ignore'), 1):
            for p in patterns:
                if re.search(p, line): print(f'{f}:{i}: Secret pattern: {line.strip()[:80]}'); ok = False
    except: pass
sys.exit(0 if ok else 1)
"
        language: python
        types: [text]
        exclude: '(\\.secrets\\.baseline|\\.pre-commit-config\\.yaml)$'
"""


def main():
    parser = argparse.ArgumentParser(description="Generate pre-commit security config")
    parser.add_argument("--repo-path", required=True, help="Path to repo root")
    parser.add_argument("--private-ip-check", action="store_true", default=True,
                        help="Include private IP detection (default: true)")
    parser.add_argument("--no-private-ip-check", dest="private_ip_check", action="store_false")
    parser.add_argument("--password-check", action="store_true", default=True,
                        help="Include password pattern detection (default: true)")
    parser.add_argument("--no-password-check", dest="password_check", action="store_false")
    args = parser.parse_args()

    config = TEMPLATE
    if args.private_ip_check:
        config += IP_HOOK
    if args.password_check:
        config += PASSWORD_HOOK

    out_path = os.path.join(args.repo_path, ".pre-commit-config.yaml")

    if os.path.exists(out_path):
        print(f"WARNING: {out_path} already exists. Overwrite? [y/N] ", end="")
        if input().strip().lower() != "y":
            print("Aborted.")
            return

    with open(out_path, "w") as f:
        f.write(config)

    print(f"\u2705 Written: {out_path}")
    print(f"\nNext steps:")
    print(f"  pip install pre-commit")
    print(f"  cd {args.repo_path}")
    print(f"  pre-commit install")
    print(f"  pre-commit run --all-files  # test on existing files")


if __name__ == "__main__":
    main()
