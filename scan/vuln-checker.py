#!/usr/bin/env python3
"""
vuln-checker.py — benign PHP2Shell (CVE-2026-109618/109619) version checker.

What it does (and ONLY this):
  * GETs each target, reads the Server / X-Powered-By banner,
  * parses the PHP version, classifies it against the public fixed-version
    matrix (EOL / VULNERABLE / PATCHED) entirely client-side, and
  * prints a per-target verdict + appends the raw request line it sent to a log.

What it does NOT do:
  * no exploit, no memory-corruption primitive, no RCE, no payload. It is a
    recon/identification tool of the same class as `nmap http-php-version` or
    `whatweb` — safe to run against your own lab.

It sends a deliberately recognisable User-Agent so you can SEE scanner traffic
in the per-version raw logs (./logs/<role>/) and then write a WAF rule that
auto-blocks it. That is the whole point: observe the checker's footprint, then
shield against it.

Usage:
  python3 scan/vuln-checker.py                      # lab default ports
  LAB_HOST=192.168.56.10 python3 scan/vuln-checker.py
  python3 scan/vuln-checker.py http://host:8080 http://host:8081
"""
import os
import re
import sys
import json
import urllib.request

# Mirror of webapp/includes/cve.php PHP2SHELL_FIXED — single source of truth.
FIXED = {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"}
CVES = "CVE-2026-109618 / CVE-2026-109619"
UA = "php2shell-vuln-checker/1.0 (+lab; benign recon)"
LOG = os.path.join(os.path.dirname(__file__), os.pardir, "logs", "checker-requests.log")


def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def classify(version):
    """Return (status, fixed_in, reason) for a PHP version string."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return "UNKNOWN", None, "could not parse a PHP version from the banner"
    major, minor = int(m.group(1)), int(m.group(2))
    branch = f"{major}.{minor}"
    if major < 8 or (major == 8 and minor <= 1):
        return "EOL_UNSUPPORTED", None, f"PHP {branch} is end-of-life; no upstream fix for {CVES}"
    fixed = FIXED.get(branch)
    if fixed is None:
        return "VULNERABLE", None, f"branch {branch} not in known matrix; verify against the advisory"
    if ver_tuple(version) < ver_tuple(fixed):
        return "VULNERABLE", fixed, f"PHP {version} < fixed {fixed} for branch {branch} — exposed to {CVES}"
    return "PATCHED", fixed, f"PHP {version} includes the fix ({fixed} or later)"


def fetch(url):
    """One benign GET. Returns (status, headers dict). No body processing."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=8) as r:
        return r.status, {k.lower(): v for k, v in r.headers.items()}


def log_request(method, url):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(f'{method} {url} UA="{UA}"\n')
    except OSError:
        pass  # logging is best-effort; never fail the check over it


def php_version_from(headers):
    xpb = headers.get("x-powered-by", "")
    m = re.search(r"PHP/([\d.]+)", xpb) or re.search(r"PHP/([\d.]+)", headers.get("server", ""))
    return m.group(1) if m else ""


def main():
    host = os.environ.get("LAB_HOST", "localhost")
    targets = sys.argv[1:] or [f"http://{host}:{p}" for p in (8080, 8081, 8082)]

    print(f"PHP2Shell benign version checker — {CVES}")
    print(f"User-Agent: {UA}\n")
    print(f'{"TARGET":<34}{"PHP":<12}{"STATUS":<17}FIXED-IN')
    print("-" * 78)

    for base in targets:
        url = base.rstrip("/") + "/"
        log_request("GET", url)
        try:
            _, headers = fetch(url)
        except Exception as e:  # noqa: BLE001 - report any transport error, keep going
            print(f"{base:<34}{'-':<12}{'UNREACHABLE':<17}({e})")
            continue
        version = php_version_from(headers)
        status, fixed, reason = classify(version) if version else ("UNKNOWN", None, "no PHP banner")
        print(f"{base:<34}{version or '?':<12}{status:<17}{fixed or 'none (EOL)'}")
        print(f'{"":<34}└ {reason}')

    print("\nDifferent PHP version -> different verdict: that version-dependent response is")
    print("exactly what a public scanner keys on. The checker's requests are logged to")
    print(f"{os.path.normpath(LOG)} and appear in the per-version raw logs under ./logs/<role>/;")
    print("block its User-Agent at the WAF to auto-drop this class of recon traffic.")


if __name__ == "__main__":
    main()
