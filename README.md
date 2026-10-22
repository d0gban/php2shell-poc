# PHP2Shell Patch-Management Lab — CVE-2026-109618 / CVE-2026-109619

A **vulnerable-by-design** lab that hosts the same small PHP web application on **three real PHP
versions** — end-of-life, outdated, and patched. It gives blue teams an authentic, production-shaped
PHP target running genuinely affected builds, so you can profile the real server fingerprint and
**develop and test firewall / WAF and detection rules** for the **PHP2Shell** vulnerability pair —
against real PHP, not an artificial stand-in, and without touching production.

> ⚠️ **Scope.** This is an isolated, loopback-only lab for **authorized, defensive security work**.
> It is **never deployed** — spin it up, use it, tear it down. Do **not** expose it on any
> internet-facing or shared host. It ships **no exploit code**; it is a target/reference environment,
> not an attack toolkit.

## The vulnerability (disclosed 2026-10-21)

| CVE | Mechanism | Severity |
|-----|-----------|----------|
| **CVE-2026-109618** | RCE via out-of-memory corruption during request cleanup | CVSS 9.2 |
| **CVE-2026-109619** | RCE via stale request-owned global state reused by a later request on the same worker | CVSS 9.2 |

Both are **unauthenticated** and trigger **before application code runs**. PHP rates the risk
**highest for Apache + `mod_php`** (also affects PHP-FPM, php-cgi, FrankenPHP, LiteSpeed).

**Fixed releases:** PHP **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. Everything older is affected;
**8.1 and earlier are end-of-life** with no upstream fix (distro backports may exist for 7.4/8.0/8.1).

## The lab matrix

| Container | Port | PHP (default tag) | Verdict |
|-----------|------|-------------------|---------|
| `php2shell-eol` | **8080** | `8.0-apache` (end-of-life) | 🔴 VULNERABLE · EOL |
| `php2shell-outdated` | **8081** | `8.3.10-apache` (< 8.3.36) | 🔴 VULNERABLE |
| `php2shell-patched` | **8082** | `8.3-apache` (≥ 8.3.36) | 🟢 PATCHED |

All three serve the **identical** web app (`./webapp`, mounted read-only). Only the PHP runtime
differs — that is the whole point.

## Deploy (one command)

```bash
bash setup.sh
```

`setup.sh` checks for Docker, builds and starts all three containers, waits until each app
answers, and prints an info panel with ports, PHP states, URLs and live verdicts. Stop with
`bash setup.sh --down`. (Equivalent manual path below.)

```bash
docker compose up --build -d
```

Then open:

- EOL (vulnerable): <http://localhost:8080>
- Outdated (vulnerable): <http://localhost:8081>
- Patched (safe): <http://localhost:8082>

Scan all three into a verdict table:

```bash
bash scan/check.sh          # or:  make scan
```

Tear down:

```bash
docker compose down         # or:  make down
```

## What each page shows

- **`/`** — the hosted web app (an "Acme Intranet Portal" landing page) with a live PHP version
  banner and a VULNERABLE / PATCHED badge.
- **`/assess.php`** — self-assessment: version→CVE verdict + an interim-mitigation config audit.
  Add `?format=json` for machine-readable output (used by the scanner).

The point is the **runtime underneath** the app. Each host runs a real PHP build and advertises it the
way a production server does (`Server` / `X-Powered-By`, error pages, default config), giving you an
authentic fingerprint to tune firewall / WAF / IDS rules against.

## No exploit code

This lab ships **no exploit, PoC, or post-exploitation tooling** — by design. The real exploit
primitive for CVE-2026-109618 / CVE-2026-109619 is not public, and this lab does not need it: its job
is to stand up **genuinely affected PHP runtimes** so defensive rules can be built and validated
against the real thing. Exposure is established by the provable facts a blue team actually works from —
which PHP build is running (version → CVE verdict) and its mitigation-config state — via `/assess.php`
and `scan/check.sh`.

## Swapping versions

Edit `.env` (`EOL_TAG`, `OLD_TAG`, `PATCHED_TAG`) and re-run `docker compose up --build -d`.
The verdict engine reads the **live** `PHP_VERSION`, so the badges stay correct for any tag.
If `php:8.3.36-apache` is not yet published on Docker Hub, the default `8.3-apache` pulls the
current patched 8.3 build; pin the exact tag once you've confirmed it exists.

## Report

A ready-to-adapt impact & remediation write-up is in [`docs/remediation.md`](docs/remediation.md).

## Layout

```
docker-compose.yml   .env   Makefile   README.md
images/{eol,outdated,patched}/Dockerfile
webapp/{index.php,assess.php,includes/{cve.php,layout.php},assets/style.css}
scan/check.sh
docs/remediation.md
```
