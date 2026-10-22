# PHP2Shell Patch-Management Lab — CVE-2026-109618 / CVE-2026-109619

A **vulnerable-by-design** lab that hosts the same small PHP web application on **three PHP
versions** — end-of-life, outdated, and patched — so you can demonstrate the **impact** of the
**PHP2Shell** vulnerability pair and the **remediation** that closes it.

> ⚠️ **Scope & ethics.** This is an isolated, loopback-only lab for **authorized security
> research and patch-management demonstration**. Do **not** deploy it on any internet-facing or
> production host, and only run it against systems you own. See the simulation disclosure below.

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
- **`/lab-impact/foothold.php`** — **labeled post-exploitation simulation**, present only on the
  vulnerable containers. On the patched container this path returns **404**.

## ⚠️ Simulation disclosure (read this)

The **real exploit primitive for CVE-2026-109618 / CVE-2026-109619 is not public**, and circulating
proof-of-concept code is unverified. This lab therefore does **not** ship a working memory-corruption
exploit. It demonstrates impact in two honest, verifiable layers:

1. **Version-based exposure** — the provable fact of which runtime is affected vs patched, plus
   mitigation-config state (`/assess.php`, `scan/check.sh`).
2. **Simulated foothold** — `foothold.php` stands in for the access an attacker holds *after* RCE.
   It runs a **fixed, read-only command allowlist** (`id`, `hostname`, `uname -a`, `php -v`,
   `ls`) with **no user-controlled command parameter**, so it proves "code runs as `www-data`"
   without being a reusable webshell.

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
lab-impact/foothold.php
scan/check.sh
docs/remediation.md
```
