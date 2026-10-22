# PHP2Shell Patch-Management Lab — CVE-2026-109618 / CVE-2026-109619

A **vulnerable-by-design** lab that hosts the same small PHP web application on **three real PHP
versions** — end-of-life, outdated, and patched. It gives blue teams an authentic, production-shaped
PHP target running genuinely affected builds, so you can profile the real server fingerprint and
**develop and test firewall / WAF and detection rules** for the **PHP2Shell** vulnerability pair —
against real PHP, not an artificial stand-in, and without touching production.

> ⚠️ **Scope.** This is an isolated lab for **authorized, defensive security work**, loopback-bound
> by default (see [Network binding](#network-binding-waf--cross-machine-testing) to reach it from a
> separate WAF/client box on an isolated segment).
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
| `php2shell-eol` | **8080** | `8.0.30-apache` (end-of-life) | 🔴 VULNERABLE · EOL |
| `php2shell-outdated` | **8081** | `8.3.10-apache` (< 8.3.36) | 🔴 VULNERABLE |
| `php2shell-patched` | **8082** | `8.3.36-apache` (= fix) | 🟢 PATCHED |

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

## Server fingerprint

Each host is deliberately left with a **production-realistic banner** (not a locked-down one) so your
rules see what a real server leaks:

- `X-Powered-By: PHP/<version>` on PHP responses (`expose_php = On`).
- `Server: Apache/2.4.x (Debian) OpenSSL/<ver> PHP/<version>` on **every** response — including
  Apache's own error pages, e.g. a 404 to a nonexistent path — because the images set
  `ServerTokens Full` + `ServerSignature On` and load `mod_ssl`.

Verify:

```bash
curl -sI http://localhost:8080/            | grep -iE 'server|x-powered-by'
curl -sI http://localhost:8080/nope-404    | grep -i server   # Apache 404 still leaks PHP + OpenSSL
```

That full fingerprint is the point for a blue team: the PHP build is observable on the vulnerable and
patched hosts alike, so you can tune version-detection / WAF rules on *which* PHP build is running,
then confirm they don't fire on the patched baseline.

**Not convinced the headers are real?** Prove it — `bash scan/verify.sh` checks, per container, that
the `Server` / `X-Powered-By` values come from the live Apache/PHP/OpenSSL runtime (matching the real
binaries and the mod_php version, leaking on Apache's own 404, absent on static files) rather than
being faked by a `header()` call in the app.

## No exploit code

This lab ships **no exploit, PoC, or post-exploitation tooling** — by design. The real exploit
primitive for CVE-2026-109618 / CVE-2026-109619 is not public, and this lab does not need it: its job
is to stand up **genuinely affected PHP runtimes** so defensive rules can be built and validated
against the real thing. Exposure is established by the provable facts a blue team actually works from —
which PHP build is running (version → CVE verdict) and its mitigation-config state — via `/assess.php`
and `scan/check.sh`.

## Testing WAF / IDS rules

`scan/waf-test.sh` generates **detection traffic** — not an exploit — so you can tune and validate
rules. It sends the PHP2Shell request *signature*: an unauthenticated multipart upload carrying the
`PHP_SESSION_UPLOAD_PROGRESS` marker (a normal, documented PHP field), plus a `control` request that
a good rule must leave alone. The probes carry no memory-corruption primitive, offsets or command
payload — they cannot achieve RCE against any target.

```bash
bash scan/waf-test.sh                        # baseline: probe the lab directly (no WAF) -> all 200
TARGET=http://waf.local:80 bash scan/waf-test.sh   # probe THROUGH your WAF -> "sig" should be blocked
```

A tuned rule blocks the `sig` / `sig-name` probes (403/406/501/reset) while leaving `control` at 200.
Each run prints a unique marker — grep it on both WAF and app logs to confirm the rule fired. Build
rules from the public detection content: a `multipart/form-data` POST whose body contains the literal
string `PHP_SESSION_UPLOAD_PROGRESS`.

## Network binding (WAF / cross-machine testing)

By default the lab publishes its ports on **`127.0.0.1` only** (`LAB_BIND` in `.env`) — reachable
from the Docker host, which is all you need when a **reverse-proxy WAF runs on the same host** and
points its upstream at `127.0.0.1:808x`. Traffic still traverses the WAF, so your rules are exercised.

To test from a **separate WAF / client box**, set `LAB_BIND` to an **isolated interface IP** (a
host-only adapter or lab-VLAN address, e.g. `192.168.56.10`) and re-run `bash setup.sh`:

```bash
# .env
LAB_BIND=192.168.56.10      # only machines on that isolated segment can reach the lab
```

Use `LAB_BIND=0.0.0.0` (all interfaces) **only** on a genuinely isolated segment with no route to
production or the internet — these are real outdated PHP runtimes and must never be reachable from an
untrusted network. `setup.sh` and `scan/check.sh` follow `LAB_BIND` automatically for their health
checks and printed URLs.

## Swapping versions

Edit `.env` (`EOL_TAG`, `OLD_TAG`, `PATCHED_TAG`) and re-run `docker compose up --build -d`.
The verdict engine reads the **live** `PHP_VERSION`, so the badges stay correct for any tag.
All three tags are pinned to concrete patch versions for reproducibility. If you switch a role to a
floating tag (e.g. `8.3-apache`), rebuild with `docker compose build --pull` so a stale local cache
can't leave an old PHP version under the "patched" role and mislabel it VULNERABLE.

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
