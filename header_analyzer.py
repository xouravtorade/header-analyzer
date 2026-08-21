#!/usr/bin/env python3
"""Inspect HTTP response headers for common security hardening gaps."""

import argparse
import sys
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS for supported browsers.",
    "Content-Security-Policy": "Restricts executable content and reduces XSS risk.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Reduces clickjacking risk.",
    "Referrer-Policy": "Controls referrer information sent with requests.",
    "Permissions-Policy": "Limits access to browser capabilities.",
}

def analyze(url, timeout=10, verify=True):
    response = requests.get(url, timeout=timeout, verify=verify, allow_redirects=True, headers={"User-Agent": "header-analyzer/1.0"})
    headers = {key.lower(): value for key, value in response.headers.items()}
    findings = []
    for name, purpose in SECURITY_HEADERS.items():
        if name.lower() not in headers:
            findings.append(("MISSING", name, purpose))
        else:
            findings.append(("PRESENT", name, headers[name.lower()]))
    return response, findings

def print_report(response, findings):
    print(f"URL: {response.url}")
    print(f"Status: {response.status_code}")
    print(f"Server: {response.headers.get('Server', 'not disclosed')}")
    print("\nSecurity headers:")
    for status, name, detail in findings:
        print(f"[{status:7}] {name}: {detail}")

def main():
    parser = argparse.ArgumentParser(description="Analyze common HTTP security headers.")
    parser.add_argument("url", help="URL to inspect, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    args = parser.parse_args()
    parsed = urlparse(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        parser.error("url must include http:// or https://")
    try:
        response, findings = analyze(args.url, args.timeout, verify=not args.insecure)
        print_report(response, findings)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
