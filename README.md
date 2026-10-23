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
| `php2shell-outdated` | **8081** | `8.4.26-apache` (< 8.4.27) | 🔴 VULNERABLE |
| `php2shell-patched` | **8082** | `8.4.27-apache` (= fix) | 🟢 PATCHED |

All three serve the **same** web app. There is one source — **`./webapp`** (the only tree in git) —
and `scan/sync-webapp.sh` generates a per-target read-only copy for each host
(`webapp-eol`, `webapp-outdated`, `webapp-patched`, all `.gitignore`'d build artifacts) that the
containers mount. `setup.sh` and `make up` run the sync automatically before `docker compose up`.

So edit **`./webapp`**, never the generated copies. The trees start identical ("only the PHP runtime
differs"); the sole deliberate divergence is applied by the sync script — the `:8081` repro host gets a
blanked `index.php` (heap-clean repro) while `:8080`/`:8082` keep the full landing page. Add any further
per-target overlay in `scan/sync-webapp.sh`, explicitly.

> Per-target PHP trigger config has an intentional split: the **EOL** image *bakes* its PHP2Shell
> trigger settings + prefork into the Dockerfile (a self-contained always-vulnerable host), while
> **outdated/patched** take their config from the mounted profile (`--stock`/`--tuned`), which is what
> makes `:8081` the tunable repro target. Don't "unify" these without rebuilding and re-checking
> `bash scan/profile.sh`.

## Scope & boundaries

This is a **defensive** lab: it audits exposure and helps you build detection and virtual
patching. It is **not an exploit framework** and ships no working exploit. The line is between
*config* and an *exploit engine*:

- **Config** *describes* the preconditions and lets you **audit or break** them. It is settings
  (`php.ini` / `conf.d`, version), inert — it never triggers the bug. This lab does this.
- **An exploit engine** actually **triggers the bug to execute code**. This lab does **not** do
  this and it will **not** be added.

| In scope — config & detection (all inert) | Out of scope — exploit engine (never added) |
|-------------------------------------------|---------------------------------------------|
| Version + config exposure audit (`/assess.php`, `scan/vuln-checker.py`) | The memory-corruption / use-after-free trigger |
| Exposure-precondition checklist (`session.upload_progress.*`, `serialize_handler`, version) | Strategy 1: `session.upload_progress` poisoning → `include()`/`require()` (LFI) sink → RCE |
| Benign attack-shaped detection markers (`scan/wafprobe.sh` — `sig` and `stages`) | Strategy 2: `session.serialize_handler` mismatch → session object-injection → RCE |
| Per-version HTTP behaviour + raw capture (`scan/profile.sh`, `logs/`) | Any `--sink` / `--save-path` / `--write-path` payload or command-execution tooling |
| WAF virtual-patch rules (`waf/`) | — |

Exposure here is proven by **version + configuration** — the verifiable facts a defender acts on.

## Deploy (one command)

```bash
bash setup.sh
```

`setup.sh` checks for Docker, builds and starts all three containers, waits until each app
answers, and prints an info panel with ports, PHP states, URLs and live verdicts. Stop with
`bash setup.sh --down`. (Equivalent manual path below.)

**Config profile.** All three hosts mount one shared PHP config so the only variable is the PHP
version. Pick which config via a flag:

```bash
bash setup.sh            # --tuned (default): config/php2shell-tune.ini — deliberately weakened
bash setup.sh --stock    # stock php.ini-production baseline (config/php2shell-stock.ini, a no-op)
```

Compare the two runs: `/assess.php`'s **Current config** column (Factory default · Current · Patched)
changes between `--stock` and `--tuned`. For the manual path, set `PHP_TUNE_INI` before compose:
`PHP_TUNE_INI=./config/php2shell-stock.ini docker compose up --build -d`.

- `config/php2shell-stock.ini` mirrors `php.ini-production` for every directive the lab audits
  (`memory_limit=128M`, `post_max_size=8M`, `display_errors=Off`, `session.upload_progress.enabled=On`).
  For the **byte-exact** upstream file, run `bash config/fetch-stock-ini.sh` (needs Docker; pulls it
  from the pinned `OLD_TAG` image).

**Apache prefork MPM.** `config/mpm-prefork.conf` is mounted into every container and sets
`MaxRequestWorkers 150` with `MaxConnectionsPerChild 0` (workers never recycled) — the official
prefork model the PHP2Shell worker-reuse vector (CVE-2026-109619, stale per-worker state) relies on.
It is an Apache MPM setting, not a `php.ini` directive. For a deterministic single-worker repro, set
`MaxRequestWorkers 1` / `ServerLimit 1` there instead (no longer the "official prefork 150" scenario).

> **For the PHP2Shell exploit repro:** the target is the **OUTDATED host on `:8081`** — exactly
> **PHP 8.4.26 + Apache prefork + mod_php** (`apache2handler`) with `MaxRequestWorkers 150`. The EOL
> (`:8080`) and patched (`:8082`) hosts stay as the matrix for comparison. Run `bash setup.sh --stock`
> (stock production config) so `:8081` is on the genuine `php.ini-production` baseline, then drive the
> repro at `http://<host>:8081`. Optional, and *not* a config change: the extra LFI/login app code can
> perturb the heap — for the cleanest repro, blank `webapp-outdated/index.php` (or serve a minimal page)
> so only the runtime is under test. This now touches `:8081` only; `:8080` and `:8082` keep their app.

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
- **`/view.php?doc=…`** — Knowledge-Base viewer with a deliberate **Local File Inclusion** (CWE-98/22).
  The concrete form of the `include()`-sink precondition `/assess.php` flags. App-layer, present on all
  three hosts. Remediation: [`docs/lfi-remediation.md`](docs/lfi-remediation.md).
- **`/login.php`** — Member login with deliberate **Session Fixation** (CWE-384): adopts a caller-set
  `?sid=` and never regenerates on login. Pairs with the LFI into a session-file → `include()` → RCE
  chain. Remediation: [`docs/session-fixation-remediation.md`](docs/session-fixation-remediation.md).

> The LFI and session-fixation flaws are **application-layer**, independent of the PHP2Shell runtime
> bug: fixed in code, not by upgrading PHP. WAF shielding: [`waf/lfi-virtual-patch.conf`](waf/lfi-virtual-patch.conf);
> detection: [`scan/DETECTION.md`](scan/DETECTION.md) §7 + [`scan/sample-logs/lfi-access.log`](scan/sample-logs/lfi-access.log).

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

**Not convinced the headers are real?** Prove it — `bash scan/profile.sh verify` checks, per container, that
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

`scan/wafprobe.sh` generates **detection traffic** — not an exploit — so you can tune and validate
rules. It sends the PHP2Shell request *signature*: an unauthenticated multipart upload carrying the
`PHP_SESSION_UPLOAD_PROGRESS` marker (a normal, documented PHP field), plus a `control` request that
a good rule must leave alone. The probes carry no memory-corruption primitive, offsets or command
payload — they cannot achieve RCE against any target.

```bash
bash scan/wafprobe.sh sig                        # baseline: probe the lab directly (no WAF) -> all 200
TARGET=http://waf.local:80 bash scan/wafprobe.sh sig   # probe THROUGH your WAF -> "sig" should be blocked
```

A tuned rule blocks the `sig` / `sig-name` probes (403/406/501/reset) while leaving `control` at 200.
Each run prints a unique marker — grep it on both WAF and app logs to confirm the rule fired. Build
rules from the public detection content: a `multipart/form-data` POST whose body contains the literal
string `PHP_SESSION_UPLOAD_PROGRESS`.

**New to this?** [`scan/DETECTION.md`](scan/DETECTION.md) is a zero-knowledge detection playbook:
how to read the logs, what each kill-chain stage looks like, the end goal of the WAF response at
each stage, and the expected output of every `scan/*.sh`. Worked log examples (normal traffic, each
kill-chain stage, and a post-exploitation crash) are in [`scan/sample-logs/`](scan/sample-logs/).

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
config/{php2shell-tune.ini,php2shell-stock.ini,fetch-stock-ini.sh,mpm-prefork.conf,rawlog.conf}  # config profiles + Apache MPM + raw-capture
webapp/{index.php,assess.php,view.php,login.php,includes/{cve.php,layout.php},content/*,assets/style.css}  # single source; sync-webapp.sh derives webapp-{eol,outdated,patched}/ (gitignored)
scan/{check.sh,profile.sh,wafprobe.sh,vuln-checker.py,sync-webapp.sh,DETECTION.md,sample-logs/*}
waf/{php2shell-virtual-patch.conf,lfi-virtual-patch.conf}
docs/{remediation.md,lfi-remediation.md,session-fixation-remediation.md,waf-tuning.md}
```
