#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="Destination URL (https://…)")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    # Validate URL scheme before touching the network
    if not args.url.startswith(("http://", "https://")):
        print(
            f"webhook: invalid URL (must start with http:// or https://): {args.url!r}",
            file=sys.stderr,
        )
        return 2

    raw = sys.stdin.read()
    if not raw.strip():
        print("webhook: stdin is empty — nothing to send", file=sys.stderr)
        return 2

    # Validate that stdin is well-formed JSON before sending
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"webhook: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 2

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print(f"webhook: malformed --header value (no key): {h!r}", file=sys.stderr)
            return 2
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
