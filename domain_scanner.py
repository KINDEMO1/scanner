#!/usr/bin/env python3
import csv
import os
import sys
import time
import random
import dns.resolver
import dns.rdatatype
import requests
from datetime import datetime, timezone

from fingerprints import FINGERPRINTS
from providers import PROVIDER_MAP

# ──────────────────────────────────────────────────────────
# Helper constants
# ──────────────────────────────────────────────────────────

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ──────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────

def identify_provider(cname_target: str) -> str:
    """Return the friendly provider name if the CNAME contains a known domain."""
    lower_cname = cname_target.lower()
    for domain, provider in PROVIDER_MAP.items():
        if domain in lower_cname:
            return provider
    return "Unknown Provider"


def check_fingerprint(cname_target: str, response_body: str) -> tuple[bool, str]:
    """
    Scan response body for known takeover signatures.
    Returns (is_vulnerable, matched_signature).
    """
    lower_cname = cname_target.lower()
    for provider_domain, signatures in FINGERPRINTS.items():
        if provider_domain in lower_cname:
            for sig in signatures:
                if sig in response_body:
                    return True, sig
            return False, "Service protected or active"
    # Fallback: scan ALL signatures regardless of CNAME (catches edge cases)
    for provider_domain, signatures in FINGERPRINTS.items():
        for sig in signatures:
            if sig in response_body:
                provider = PROVIDER_MAP.get(provider_domain, provider_domain)
                return True, f"{sig} (matched {provider})"
    return False, "No known signature"


# ──────────────────────────────────────────────────────────
# Risk classification (with MEDIUM hygiene)
# ──────────────────────────────────────────────────────────

def classify_risk(
    dns_status: str,
    http_status: int,
    fingerprint: str,
    http_error: str,
    provider: str,
    cname_target: str,
) -> tuple[str, str]:
    """
    Classify risk based on:
      - 3rd-party provider
      - HTTP behavior
      - Fingerprints

    Behavior:
      - CRITICAL/HIGH for true/likely takeover.
      - MEDIUM for self-pointing / misconfigured non–3rd-party A/CNAME
        (low likelihood, some potential).
      - INFO/LOW for hygiene and clearly safe cases.
    """

    clean_cname = cname_target.lower().rstrip(".")

    # Hard-coded safe Google pointers
    if clean_cname in ["google.com", "www.google.com", "maps.google.com"]:
        return "LOW", "Pointed to Google Main (Safe/Not Exploitable)"
    if provider == "Unknown Provider" and "google.com" in clean_cname:
        return "LOW", "Pointed to Generic Google (Safe)"

    is_third_party = provider != "Unknown Provider"
    is_broken = http_status == 0 or http_status >= 400
    has_fingerprint = fingerprint not in (
        "",
        "No known signature",
        "Service protected or active",
    )
    has_pointer = dns_status in ("CNAME", "A")

    # MEDIUM: DNS Hygiene – self-pointing or misconfigured non–3rd-party
    if dns_status == "CNAME" and is_broken and not is_third_party:
        return "MEDIUM", "DNS Hygiene: Self-Pointing or Misconfigured CNAME (Low Likelihood, Some Potential)"

    if dns_status == "A" and is_broken and not is_third_party:
        return "MEDIUM", "DNS Hygiene: Misconfigured/Dead A Record (Low Likelihood, Some Potential)"

    # CRITICAL: 3rd-party + broken + fingerprint
    if is_third_party and is_broken and has_fingerprint:
        return "CRITICAL", "Confirmed Subdomain Takeover (All 3 Conditions Met)"

    # CRITICAL: 3rd-party + 200 + fingerprint (Unbounce/WordPress style)
    if is_third_party and http_status == 200 and has_fingerprint:
        return "CRITICAL", "Subdomain Takeover (Service Responding 200 with Fingerprint)"

    # HIGH: 3rd-party + broken, no fingerprint
    if is_third_party and is_broken:
        return "HIGH", "Dangling Pointer to 3rd Party (No Fingerprint)"

    # HIGH: fingerprint + broken but provider unknown
    if (not is_third_party) and has_fingerprint and is_broken:
        return "HIGH", "Suspicious Content (Fingerprint Found but Provider Unknown)"

    # LOW: No DNS
    if dns_status == "NXDOMAIN":
        return "LOW", "No DNS Record - Not Exploitable"

    # INFO: Active pointer, no bad fingerprint
    if has_pointer and http_status == 200:
        return "INFO", "Active Subdomain - Verify Ownership"

    # Fallback: generic misconfig
    return "INFO", "Orphaned or Misconfigured Subdomain"


# ──────────────────────────────────────────────────────────
# Security Issue label
# ──────────────────────────────────────────────────────────

def determine_security_issue(
    dns_status: str,
    http_status: int,
    fingerprint: str,
    risk_level: str,
) -> str:
    """Produce the Security Issue label for the CSV."""
    has_pointer = dns_status in ("CNAME", "A")
    is_vulnerable_fp = fingerprint not in (
        "",
        "No known signature",
        "Service protected or active",
    )

    # Map directly by risk_level first
    if risk_level == "CRITICAL":
        return "Subdomain Takeover"
    if risk_level == "HIGH":
        return "Dangling DNS Record"
    if risk_level == "MEDIUM":
        return "DNS Hygiene Misconfiguration"

    # For INFO/LOW, keep more granular behavior
    if has_pointer and http_status == 200 and not is_vulnerable_fp:
        return "None - Active Service"
    if dns_status == "NXDOMAIN":
        return "None - NXDOMAIN"
    if has_pointer and (http_status >= 400 or http_status == 0):
        return "Potential Misconfiguration"

    return "Potential Misconfiguration"


# ──────────────────────────────────────────────────────────
# DNS lookup
# ──────────────────────────────────────────────────────────

def dns_lookup(subdomain: str) -> tuple[str, str, str]:
    """
    1. Try CNAME resolution
    2. Fall back to A record
    3. Return (dns_status, cname_target, raw_lookup_text)
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 8
    resolver.lifetime = 8

    # CNAME
    try:
        answers = resolver.resolve(subdomain, "CNAME")
        targets = [str(rr.target).rstrip(".") for rr in answers]
        cname = targets[0] if targets else ""
        if cname:
            # Check if CNAME target itself resolves
            cname_resolves = True
            try:
                resolver.resolve(cname, "A")
            except Exception:
                cname_resolves = False
            note = "" if cname_resolves else " [CNAME target NXDOMAIN]"
            return "CNAME", cname, f"CNAME -> {cname}{note}"
    except Exception:
        pass

    # A record
    try:
        answers = resolver.resolve(subdomain, "A")
        ips = [str(rr.address) for rr in answers]
        ip = ips[0]
        return "A", ip, f"A -> {', '.join(ips)}"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN", "", "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "NXDOMAIN", "", "No DNS Answer"
    except dns.resolver.NoNameservers:
        return "NXDOMAIN", "", "No Nameservers"
    except Exception as exc:
        return "NXDOMAIN", "", f"DNS Error: {type(exc).__name__}: {exc}"


# ──────────────────────────────────────────────────────────
# HTTP probe
# ──────────────────────────────────────────────────────────

def http_probe(subdomain: str) -> dict:
    """
    Perform HTTP GET (with HTTPS fallback).
    Returns dict with: status, body, error, server_header.
    """
    result = {"status": 0, "body": "", "error": "", "server_header": ""}

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url,
                timeout=15,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                allow_redirects=True,
                verify=False,  # Some dangling certs are invalid
            )
            result["status"] = resp.status_code
            result["body"] = resp.text[:50000]
            result["server_header"] = resp.headers.get("Server", "")
            result["error"] = ""
            return result
        except requests.exceptions.SSLError:
            if scheme == "https":
                continue
            result["error"] = "SSL Error"
        except requests.exceptions.Timeout:
            result["error"] = "Timeout"
            return result
        except requests.exceptions.ConnectionError as e:
            err_str = str(e)
            if "404" in err_str:
                result["status"] = 404
                result["error"] = "Connection Error (404)"
            elif "403" in err_str:
                result["status"] = 403
                result["error"] = "Connection Error (403)"
            else:
                result["error"] = "Connection Failed"
            if scheme == "http":
                return result
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
            if scheme == "http":
                return result

    return result


# ──────────────────────────────────────────────────────────
# Full scan pipeline
# ──────────────────────────────────────────────────────────

OUTPUT_COLUMNS = [
    "Subdomain",
    "CNAME (Pointed To)",
    "DNS Status",
    "HTTP Status",
    "Provider",
    "Signature",
    "DNS Lookup Result",
    "Security Issue",
    "Risk Level",
    "Risk Label",
    "Server Header",
    "Scanned At",
]


def scan_subdomain(subdomain: str) -> dict:
    """Run DNS + HTTP + classification for a single subdomain."""
    # DNS
    dns_status, cname_target, dns_lookup_text = dns_lookup(subdomain)
    if not cname_target:
        cname_target = subdomain

    # HTTP (stealth delay)
    time.sleep(random.uniform(1.5, 3.5))
    probe = http_probe(subdomain)
    http_status = probe["status"]
    body = probe["body"]
    http_error = probe["error"]
    server_header = probe["server_header"]

    # Provider + fingerprint
    provider = identify_provider(cname_target)
    is_vuln, fingerprint = check_fingerprint(cname_target, body)

    # Risk + issue
    risk_level, risk_label = classify_risk(
        dns_status,
        http_status,
        fingerprint,
        http_error,
        provider,
        cname_target,
    )
    security_issue = determine_security_issue(
        dns_status,
        http_status,
        fingerprint,
        risk_level,
    )

    # Signature
    if is_vuln and fingerprint:
        signature = f"{provider} - {fingerprint}"
    elif http_error and http_status == 0:
        signature = f"{provider} - {http_error}"
    elif http_status > 0:
        signature = f"{provider} - HTTP {http_status}"
    else:
        signature = f"{provider} - No Response"

    # HTTP status display
    if http_status == 0:
        http_display = f"0 ({http_error})" if http_error else "0 (No Response)"
    else:
        http_display = str(http_status)

    return {
        "Subdomain": subdomain,
        "CNAME (Pointed To)": cname_target,
        "DNS Status": dns_status,
        "HTTP Status": http_display,
        "Provider": provider,
        "Signature": signature,
        "DNS Lookup Result": dns_lookup_text,
        "Security Issue": security_issue,
        "Risk Level": risk_level,
        "Risk Label": risk_label,
        "Server Header": server_header,
        "Scanned At": datetime.now(timezone.utc).isoformat(),
    }


# ──────────────────────────────────────────────────────────
# Input parser + main
# ──────────────────────────────────────────────────────────

def parse_input_file(filepath: str) -> list[str]:
    """Read subdomains from a CSV or plain-text file (first column)."""
    subdomains: list[str] = []
    with open(filepath, newline="", encoding="utf-8") as f:
        sample = f.read(2048)
        f.seek(0)
        first_line = sample.split("\n")[0].lower()
        skip_header = "subdomain" in first_line or "domain" in first_line

        reader = csv.reader(f)
        for idx, row in enumerate(reader):
            if idx == 0 and skip_header:
                continue
            if row and row[0].strip():
                val = row[0].strip()
                # Strip protocol if someone pasted full URLs
                for prefix in ("https://", "http://"):
                    if val.startswith(prefix):
                        val = val[len(prefix):]
                val = val.rstrip("/")
                if val:
                    subdomains.append(val)
    return subdomains


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_dir, "targets.txt")
    output_file = os.path.join(script_dir, "scan_results.csv")

    if not os.path.isfile(input_file):
        print(f"Error: File not found -- {input_file}", file=sys.stderr)
        print(f"Please create a 'targets.txt' file in:", file=sys.stderr)
        print(f"  {script_dir}", file=sys.stderr)
        print(f"\nFormat: one subdomain per line, e.g.:", file=sys.stderr)
        print(f"  blog.example.com", file=sys.stderr)
        print(f"  shop.example.com", file=sys.stderr)
        sys.exit(1)

    subdomains = parse_input_file(input_file)
    if not subdomains:
        print("Error: No subdomains found in targets.txt.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(subdomains)} subdomain(s) from targets.txt")
    print(f"[*] Output -> {output_file}")
    print(f"[*] Scanning with stealth delay (1.5-3.5s between requests)\n")

    results: list[dict] = []

    for i, sub in enumerate(subdomains, 1):
        print(f"[{i}/{len(subdomains)}] {sub} ...", end=" ", flush=True)
        row = scan_subdomain(sub)
        results.append(row)
        status = row["HTTP Status"]
        risk = row["Risk Level"]
        issue = row["Security Issue"]
        print(f"DNS={row['DNS Status']}  HTTP={status}  Risk={risk}  Issue={issue}")

    # Write CSV
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(results)

    # Summary
    total = len(results)
    critical = sum(1 for r in results if r["Risk Level"] == "CRITICAL")
    high = sum(1 for r in results if r["Risk Level"] == "HIGH")
    medium = sum(1 for r in results if r["Risk Level"] == "MEDIUM")
    info = sum(1 for r in results if r["Risk Level"] == "INFO")
    low = sum(1 for r in results if r["Risk Level"] == "LOW")

    print(f"\n{'=' * 60}")
    print(f"  SCAN COMPLETE -- {total} subdomain(s)")
    print(f"{'=' * 60}")
    print(f"  CRITICAL : {critical}  (Confirmed Takeover)")
    print(f"  HIGH     : {high}      (Dangling / Orphaned)")
    print(f"  MEDIUM   : {medium}    (DNS Hygiene / Misconfig)")
    print(f"  INFO     : {info}      (Misconfigured / Review)")
    print(f"  LOW      : {low}       (NXDOMAIN / Safe)")
    print(f"{'=' * 60}")
    print(f"\n[+] Results saved to {output_file}")

    if critical > 0:
        print(f"\n[!] WARNING: {critical} CRITICAL finding(s) detected!")
        print(f"    These subdomains have confirmed takeover fingerprints.")
        print(f"    Immediate remediation recommended.\n")


if __name__ == "__main__":
    main()