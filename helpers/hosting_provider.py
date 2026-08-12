#!/usr/bin/env python3
"""Best-effort hosting/provider identification from DNS, PTR, IP ranges and WHOIS."""
from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Signal:
    provider: str
    evidence: str
    confidence: str


def run(argv: list[str], timeout: int = 10) -> str:
    try:
        p = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return p.stdout.strip()


def host(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    value = (parsed.hostname or "").rstrip(".").lower()
    if not value:
        raise ValueError("invalid hostname")
    return value.encode("idna").decode("ascii")


def dig(name: str, rrtype: str) -> list[str]:
    return [x.rstrip(".") for x in run(["dig", "+short", rrtype, name]).splitlines() if x.strip()]


def ptr(ip: str) -> list[str]:
    return [x.rstrip(".") for x in run(["dig", "+short", "-x", ip]).splitlines() if x.strip()]


def first_ip(values: list[str]) -> str | None:
    for v in values:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            pass
    return None


def in_net(ip: str | None, cidr: str) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
    except ValueError:
        return False


def whois_org(ip: str | None) -> str | None:
    if not ip:
        return None
    data = run(["whois", ip])
    for pattern in (
        r"^(?:org-name|OrgName|Organization):\s*(.+)$",
        r"^netname:\s*(.+)$",
        r"^descr:\s*(.+)$",
    ):
        m = re.search(pattern, data, re.I | re.M)
        if m:
            value = m.group(1).strip()
            if value and "REDACTED" not in value.upper():
                return value
    return None


def guess(domain: str) -> Signal | None:
    cnames = dig(domain, "CNAME") + dig(f"www.{domain}", "CNAME")
    a = first_ip(dig(domain, "A"))
    aaaa = first_ip(dig(domain, "AAAA"))
    chosen_ip = a or aaaa
    ptrs = ptr(chosen_ip) if chosen_ip else []
    cname_blob = " ".join(cnames).lower()
    ptr_blob = " ".join(ptrs).lower()

    cname_sigs = (
        ("squarespace.com", "Squarespace"), ("shopify.com", "Shopify"),
        ("wixdns.net", "Wix"), ("hostinger", "Hostinger"),
        ("webflow", "Webflow"), ("pages.dev", "Cloudflare Pages"),
        ("github.io", "GitHub Pages"), ("netlify", "Netlify"),
        ("vercel", "Vercel"), ("azurewebsites.net", "Microsoft Azure App Service"),
        ("cloudfront.net", "Amazon CloudFront"), ("fastly.net", "Fastly"),
    )
    for needle, provider in cname_sigs:
        if needle in cname_blob:
            return Signal(provider, f"CNAME: {', '.join(cnames)}", "high")

    if chosen_ip == "104.37.39.71":
        return Signal("SSL Redirect Proxy / default A record", chosen_ip, "high")
    for cidr, provider in (
        ("104.16.0.0/13", "Cloudflare"), ("172.64.0.0/13", "Cloudflare"),
        ("104.37.39.0/24", "Digital Garden"), ("195.47.247.0/24", "One.com"),
    ):
        if in_net(chosen_ip, cidr):
            return Signal(provider, f"IP range: {chosen_ip} in {cidr}", "medium")

    for needle, provider in (
        ("tornado-node.net", "SYSE"), ("tornado.no", "SYSE"),
        ("proisp.no", "ProISP"), ("webpod", "One.com / ProISP infrastructure"),
        ("domeneshop.no", "Domeneshop"), ("domainname.shop", "Domeneshop"),
    ):
        if needle in ptr_blob:
            return Signal(provider, f"PTR: {', '.join(ptrs)}", "medium")

    org = whois_org(chosen_ip)
    if org:
        return Signal(org, f"WHOIS organisation for {chosen_ip}", "low")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--plain", action="store_true", help="Only print the provider name")
    ns = ap.parse_args()
    try:
        domain = host(ns.target)
    except (ValueError, UnicodeError) as exc:
        print(f"error: {exc}")
        return 2
    signal = guess(domain)
    if not signal:
        print("Unknown" if ns.plain else "Provider: Unknown")
        return 1
    if ns.plain:
        print(signal.provider)
    else:
        print(f"Provider: {signal.provider}")
        print(f"Confidence: {signal.confidence}")
        print(f"Evidence: {signal.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
