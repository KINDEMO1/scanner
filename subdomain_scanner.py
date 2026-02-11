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

# ──────────────────────────────────────────────────────────
# Fingerprint DB  (from classify-subdomain.tsx)
# Keyed by CNAME domain fragment -> list of body signatures
# ──────────────────────────────────────────────────────────

FINGERPRINTS: dict[str, list[str]] = {
    "s3.amazonaws.com":           ["NoSuchBucket", "The specified bucket does not exist"],
    "cloudfront.amazonaws.com":   ["NoSuchBucket", "InvalidBucketName", "Bad Request", "ERROR: The request could not be satisfied"],
    "elasticbeanstalk.com":       ["404 Not Found"],
    "googlehosted.com":           ["The requested URL / was not found on this server", "Not Found"],
    "c.storage.googleapis.com":   ["NoSuchBucket", "The specified bucket does not exist"],
    "github.io":                  ["There isn't a GitHub Pages site here", "There is no GitHub Pages site"],
    "herokuapp.com":              ["No such app", "Application Error", "no-such-app"],
    "azurewebsites.net":          ["404 Web Site not found", "Resource not found"],
    "cloudapp.azure.com":         ["404 Web Site not found"],
    "azure-api.net":              ["Resource not found"],
    "azureedge.net":              ["<h2>Our services aren't available right now</h2>", "400 - Bad Request"],
    "trafficmanager.net":         ["404 Not Found"],
    "blob.core.windows.net":     ["BlobNotFound", "The specified blob does not exist"],
    "myshopify.com":              ["Sorry, this shop is currently unavailable", "Only one step left"],
    "tumblr.com":                 ["Whatever you were looking for doesn't currently exist", "There's nothing here"],
    "wordpress.com":              ["Do you want to register"],
    "bitbucket.io":               ["Repository not found"],
    "ghost.io":                   ["The thing you were looking for is no longer here", "Ghost: The Professional Publishing Platform"],
    "vercel.app":                 ["DEPLOYMENT_NOT_FOUND", "Project not found"],
    "netlify.app":                ["Page Not Found", "Site not found", "Not Found - Request ID"],
    "netlify.com":                ["Page Not Found", "Site not found"],
    "pantheonsite.io":            ["404 error unknown site", "The gods are wise"],
    "zendesk.com":                ["Help Center Closed", "Oops, this help center"],
    "helpjuice.com":              ["We could not find what you're looking for"],
    "helpscoutdocs.com":          ["No settings were found for this company"],
    "statuspage.io":              ["You are being redirected", "Status page"],
    "freshdesk.com":              ["May not be configured"],
    "uservoice.com":              ["This UserVoice subdomain is currently available"],
    "surge.sh":                   ["project not found"],
    "bitbucket.org":              ["Repository not found"],
    "smartling.com":              ["Domain is not configured"],
    "acquia-test.co":             ["Web Site Not Found"],
    "proposify.biz":              ["If you need immediate assistance"],
    "simplebooklet.com":          ["We can't find this SimpleBooklet"],
    "getresponse.com":            ["With GetResponse"],
    "vend.com":                   ["Oops, this page doesn't exist"],
    "aftership.app":              ["Oops.</h2>", "The page you're looking for"],
    "aha.io":                     ["There is no portal here"],
    "tictail.com":                ["to target URL", "Starting URL"],
    "brightcove.com":             ["<p class=\"bc-gallery-error-code\">"],
    "bigcartel.com":              ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
    "campaignmonitor.com":        ["Double check the URL", "Trying to access your account?"],
    "cargocollective.com":        ["404 Not Found"],
    "feedpress.me":               ["The feed has not been found."],
    "flexport.com":               ["You've reached a dead end"],
    "frontify.com":               ["404 - Page not found"],
    "gemfury.com":                ["404: This page could not be found"],
    "intercom.help":              ["Uh oh. That page doesn't exist"],
    "landingi.com":               ["It looks like you're lost"],
    "mashery.com":                ["Unrecognized domain"],
    "ngrok.io":                   ["ngrok.io not found", "Tunnel not found"],
    "pingdom.com":                ["Public Report Not Activated", "Sorry, couldn't find the status page"],
    "readme.io":                  ["Project doesnt exist"],
    "smugmug.com":                ["Page Not Found"],
    "strikingly.com":             ["But if you're looking to build your own website"],
    "teamwork.com":               ["Oops - We didn't find your site"],
    "thinkific.com":              ["You may have mistyped the address"],
    "tilda.ws":                   ["Domain has been assigned"],
    "uberflip.com":               ["Non-hub polygon  (404)"],
    "unbounce.com":               ["The requested URL was not found on this server"],
    "uptimerobot.com":            ["page not found"],
    "webflow.io":                 ["The page you are looking for doesn't exist", "Page not found"],
    "wishpond.com":               ["https://www.wishpond.com/404"],
    "worksites.net":              ["Hello! Sorry, but the website"],
    "wufoo.com":                  ["Hmmm....this" , "looks like you've stumbled"],
}

PROVIDER_MAP: dict[str, str] = {
    "s3.amazonaws.com":           "AWS S3",
    "cloudfront.amazonaws.com":   "AWS CloudFront",
    "elasticbeanstalk.com":       "AWS Elastic Beanstalk",
    "googlehosted.com":           "GCP Cloud Storage",
    "c.storage.googleapis.com":   "GCP Cloud Storage",
    "azurewebsites.net":          "Azure App Service",
    "cloudapp.azure.com":         "Azure Cloud App",
    "azure-api.net":              "Azure API Management",
    "azureedge.net":              "Azure CDN",
    "trafficmanager.net":         "Azure Traffic Manager",
    "blob.core.windows.net":     "Azure Blob Storage",
    "github.io":                  "GitHub Pages",
    "herokuapp.com":              "Heroku",
    "myshopify.com":              "Shopify",
    "netlify.app":                "Netlify",
    "netlify.com":                "Netlify",
    "vercel.app":                 "Vercel",
    "ghost.io":                   "Ghost Pro",
    "bitbucket.io":               "Bitbucket",
    "bitbucket.org":              "Bitbucket",
    "wordpress.com":              "WordPress.com",
    "tumblr.com":                 "Tumblr",
    "pantheonsite.io":            "Pantheon",
    "zendesk.com":                "Zendesk",
    "helpjuice.com":              "Helpjuice",
    "helpscoutdocs.com":          "HelpScout",
    "statuspage.io":              "Atlassian Statuspage",
    "freshdesk.com":              "Freshdesk",
    "uservoice.com":              "UserVoice",
    "surge.sh":                   "Surge.sh",
    "smartling.com":              "Smartling",
    "acquia-test.co":             "Acquia",
    "proposify.biz":              "Proposify",
    "simplebooklet.com":          "SimpleBooklet",
    "getresponse.com":            "GetResponse",
    "vend.com":                   "Vend",
    "aftership.app":              "AfterShip",
    "aha.io":                     "Aha!",
    "tictail.com":                "Tictail",
    "brightcove.com":             "Brightcove",
    "bigcartel.com":              "Big Cartel",
    "campaignmonitor.com":        "Campaign Monitor",
    "cargocollective.com":        "Cargo Collective",
    "feedpress.me":               "FeedPress",
    "frontify.com":               "Frontify",
    "gemfury.com":                "Gemfury",
    "intercom.help":              "Intercom",
    "landingi.com":               "Landingi",
    "mashery.com":                "Mashery (TIBCO)",
    "ngrok.io":                   "ngrok",
    "pingdom.com":                "Pingdom",
    "readme.io":                  "ReadMe",
    "smugmug.com":                "SmugMug",
    "strikingly.com":             "Strikingly",
    "teamwork.com":               "Teamwork",
    "thinkific.com":              "Thinkific",
    "tilda.ws":                   "Tilda",
    "uberflip.com":               "Uberflip",
    "unbounce.com":               "Unbounce",
    "uptimerobot.com":            "UptimeRobot",
    "webflow.io":                 "Webflow",
    "wishpond.com":               "Wishpond",
    "worksites.net":              "Worksites",
    "wufoo.com":                  "Wufoo",
    "flexport.com":               "Flexport",
}


# ──────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def identify_provider(cname_target: str) -> str:
    """Return the friendly provider name if the CNAME contains a known domain."""
    for domain, provider in PROVIDER_MAP.items():
        if domain in cname_target.lower():
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


def classify_risk(
    dns_status: str,
    http_status: int,
    fingerprint: str,
    http_error: str,
) -> tuple[str, str]:
    """
    Classify risk using the same logic as classify-subdomain.tsx.
    Returns (severity, label).
    """
    is_vulnerable_fp = fingerprint not in (
        "",
        "No known signature",
        "Service protected or active",
    )
    has_pointer = dns_status in ("CNAME", "A")
    is_broken = http_status == 0 or http_status >= 400

    # CRITICAL: CNAME/A exists + known takeover fingerprint + broken HTTP
    if has_pointer and is_vulnerable_fp and is_broken:
        return "CRITICAL", "Confirmed Subdomain Takeover"

    # CRITICAL: CNAME/A exists + known takeover fingerprint + HTTP 200
    # (service is serving default unclaimed page)
    if has_pointer and is_vulnerable_fp and http_status == 200:
        return "CRITICAL", "Subdomain Takeover (Unclaimed Service Responding 200)"

    # HIGH: CNAME/A exists + broken HTTP but no known fingerprint
    if has_pointer and is_broken:
        # Distinguish between truly orphaned (no server at all) and just 404
        if http_status == 0 and http_error in ("Connection Failed", "Timeout"):
            return "HIGH", "Orphaned DNS Record (No Server Responding)"
        return "HIGH", "Dangling Subdomain - Manual Validation Required"

    # LOW: No DNS record at all
    if dns_status == "NXDOMAIN":
        return "LOW", "No DNS Record - Not Exploitable"

    # MEDIUM: Everything else (CNAME/A exists, HTTP works, no fingerprint)
    if has_pointer and http_status == 200:
        return "MEDIUM", "Active Subdomain - Verify Ownership"

    return "MEDIUM", "Orphaned or Misconfigured Subdomain"


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

    if risk_level == "CRITICAL":
        return "Subdomain Takeover"
    if has_pointer and http_status == 200 and not is_vulnerable_fp:
        return "None - Active Service"
    if has_pointer and (http_status >= 400 or http_status == 0):
        return "Dangling DNS Record"
    if dns_status == "NXDOMAIN":
        return "None - NXDOMAIN"
    return "Potential Misconfiguration"


# ──────────────────────────────────────────────────────────
# DNS lookup  (mirrors check_assets.ps1 Resolve-DnsName)
# ──────────────────────────────────────────────────────────

def dns_lookup(subdomain: str) -> tuple[str, str, str]:
    """
    1) Try CNAME resolution
    2) Fall back to A record
    3) Return (dns_status, cname_target, raw_lookup_text)
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 8
    resolver.lifetime = 8

    # --- CNAME ---
    try:
        answers = resolver.resolve(subdomain, "CNAME")
        targets = [str(rr.target).rstrip(".") for rr in answers]
        cname = targets[0] if targets else ""
        if cname:
            # Also check if the CNAME target itself resolves (dangling check)
            cname_resolves = True
            try:
                resolver.resolve(cname, "A")
            except Exception:
                cname_resolves = False
            note = "" if cname_resolves else " [CNAME target NXDOMAIN]"
            return "CNAME", cname, f"CNAME -> {cname}{note}"
    except Exception:
        pass

    # --- A record ---
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
# HTTP probe  (combines deep_evidence.ps1 + header_audit.ps1)
# Captures: status code, body, Server header, even from errors
# ──────────────────────────────────────────────────────────

def http_probe(subdomain: str) -> dict:
    """
    Perform HTTP GET (with HTTPS fallback).
    Returns dict with: status, body, error, server_header.
    Captures status codes from error responses (like deep_evidence.ps1).
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
            result["body"] = resp.text[:50000]  # Cap body to 50KB
            result["server_header"] = resp.headers.get("Server", "")
            result["error"] = ""
            return result
        except requests.exceptions.SSLError:
            # HTTPS failed with SSL error, try HTTP next
            if scheme == "https":
                continue
            result["error"] = "SSL Error"
        except requests.exceptions.Timeout:
            result["error"] = "Timeout"
            return result
        except requests.exceptions.ConnectionError as e:
            err_str = str(e)
            # Try to extract status code from connection error if present
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
# Full scan pipeline for one subdomain
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

    # 1 -- DNS
    dns_status, cname_target, dns_lookup_text = dns_lookup(subdomain)
    if not cname_target:
        cname_target = subdomain

    # 2 -- HTTP  (with stealth delay like check_assets.ps1)
    time.sleep(random.uniform(1.5, 3.5))
    probe = http_probe(subdomain)
    http_status = probe["status"]
    body = probe["body"]
    http_error = probe["error"]
    server_header = probe["server_header"]

    # 3 -- Provider identification
    provider = identify_provider(cname_target)

    # 4 -- Fingerprint scan
    is_vuln, fingerprint = check_fingerprint(cname_target, body)

    # 5 -- Risk classification
    risk_level, risk_label = classify_risk(dns_status, http_status, fingerprint, http_error)

    # 6 -- Security issue label
    security_issue = determine_security_issue(dns_status, http_status, fingerprint, risk_level)

    # 7 -- Build Signature column: "<Provider> - <Code or Message>"
    if is_vuln and fingerprint:
        signature = f"{provider} - {fingerprint}"
    elif http_error and http_status == 0:
        signature = f"{provider} - {http_error}"
    elif http_status > 0:
        signature = f"{provider} - HTTP {http_status}"
    else:
        signature = f"{provider} - No Response"

    # 8 -- HTTP Status display
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
    # Suppress InsecureRequestWarning from urllib3 (we use verify=False)
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
    low = sum(1 for r in results if r["Risk Level"] == "LOW")

    print(f"\n{'=' * 60}")
    print(f"  SCAN COMPLETE -- {total} subdomain(s)")
    print(f"{'=' * 60}")
    print(f"  CRITICAL : {critical}  (Confirmed Takeover)")
    print(f"  HIGH     : {high}  (Dangling / Orphaned)")
    print(f"  MEDIUM   : {medium}  (Misconfigured / Review)")
    print(f"  LOW      : {low}  (NXDOMAIN / Safe)")
    print(f"{'=' * 60}")
    print(f"\n[+] Results saved to {output_file}")

    if critical > 0:
        print(f"\n[!] WARNING: {critical} CRITICAL finding(s) detected!")
        print(f"    These subdomains have confirmed takeover fingerprints.")
        print(f"    Immediate remediation recommended.\n")


if __name__ == "__main__":
    main()
