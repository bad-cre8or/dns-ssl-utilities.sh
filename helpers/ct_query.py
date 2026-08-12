#!/usr/bin/env python3
"""Format crt.sh JSON results without requiring jq."""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import quote
from urllib.request import Request, urlopen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("domain")
    ap.add_argument("--limit", type=int, default=40)
    ns = ap.parse_args()
    url = f"https://crt.sh/?q={quote(ns.domain)}&output=json"
    req = Request(url, headers={"User-Agent": "dns-ssl-utilities/2.0"})
    try:
        with urlopen(req, timeout=15) as response:
            rows = json.load(response)
    except Exception as exc:
        print(f"CT query failed: {exc}", file=sys.stderr)
        return 1

    seen: dict[str, tuple[str, str]] = {}
    for row in rows:
        issuer = str(row.get("issuer_name", "")).replace("\n", " ")
        not_after = str(row.get("not_after", ""))
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if name:
                seen[name] = (not_after, issuer)

    if not seen:
        print("No CT entries found")
        return 1
    for index, (name, (expiry, issuer)) in enumerate(sorted(seen.items()), start=1):
        if index > ns.limit:
            print(f"... {len(seen) - ns.limit} more unique names")
            break
        issuer_short = issuer.split(",")[0][:70]
        print(f"{name}\t{expiry}\t{issuer_short}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
