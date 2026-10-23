# PHP2Shell — Detection Playbook (zero-knowledge guide)

**CVE-2026-109618 / CVE-2026-109619**

Written for a blue teamer who is new to WAF and detection work. No prior knowledge
is assumed. This guide covers:

1. What a WAF is, what "detection" means, and where the evidence lives.
2. How to tell from the logs that someone is **probing, performing reconnaissance,
   exploiting, or operating post-exploitation** against PHP2Shell.
3. What the **WAF response should be (the end goal)** at each stage — and how to
   confirm it is correct.
4. The **expected output** of each `scan/*.sh` script.

> Companion files:
> - [`docs/waf-tuning.md`](../docs/waf-tuning.md) — how to *deploy* and *tune* the rules.
> - [`waf/php2shell-virtual-patch.conf`](../waf/php2shell-virtual-patch.conf) — the actual ModSecurity rules (IDs `1000090`–`1000210`).
>
> This `DETECTION.md` is the **"how to read it"** guide; those are the
> **"how to block it"** guides.

---

## 0. Concepts you need first (30 seconds)

| Term | In plain terms |
|------|----------------|
| **WAF** (Web Application Firewall) | A guard that sits in front of the web server. It inspects each HTTP request (URL, headers, body) and can **allow, block, or alert**. It cannot see the memory bug inside PHP — it sees **HTTP only**. |
| **Detection** | **Knowing** that something malicious is happening — derived from logs and alerts. It is not yet blocking. |
| **Prevention** | The actual **blocking** (403, connection reset). This is distinct from detection. |
| **IOC** (Indicator of Compromise) | A concrete trace — e.g. a specific string in the request body — that is a "tell" of the attack. |
| **Kill chain** | The **successive stages** of an attack: passive recon → active recon → exploitation → post-exploitation. Each stage has a different trace and a different correct response. |

**The most important fact about PHP2Shell:** the bug runs **inside PHP, before the
application code runs**. That means a WAF is only a **stopgap** (defense-in-depth) —
the only complete fix is to **upgrade PHP** to `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`
(or a vendor backport for EOL branches). A WAF buys you *time* and *visibility*, not
immunity.

---

## 1. Where the evidence lives (the logs)

The lab writes a raw HTTP capture to `logs/<role>/` on your host (bind-mounted from
each container — see `docker-compose.yml`). Two files matter most:

| File | Contents | Format |
|------|----------|--------|
| `logs/<role>/lab_capture.log` | One line per HTTP request (the access log) | the `labcap` format — see [`config/rawlog.conf`](../config/rawlog.conf) |
| `logs/<role>/error.log` | PHP errors and Apache worker crashes | standard Apache/PHP error log |

A `labcap` line looks like this (learn to read it):

```
<IP> <timestamp> "POST /index.php HTTP/1.1" 200 1234 ct="multipart/form-data; boundary=..." len=65611 ua="curl/8.4.0" xff="-"
          │          │                        │    │    └ request Content-Type ────────┘    │       │           └ X-Forwarded-For
          │          │                        │    └ bytes returned                          │       └ User-Agent
          │          │                        └ HTTP status code                              └ Content-Length (request body size)
          │          └ when
          └ method + path + protocol
```

> `<role>` = `eol`, `outdated`, or `patched`. If your build loads `mod_dumpio`, the
> **raw body bytes** are also in `error.log` — that is where you will see the literal
> `PHP_SESSION_UPLOAD_PROGRESS` string.

> **Want to see the shapes immediately?** Worked examples are in
> [`scan/sample-logs/`](sample-logs/): `normal-access.log` (clean),
> `killchain-access.log` (the three stages), `modsec-alerts.log` (WAF alerts), and
> `post-exploitation-error.log` (crash evidence). Use them as a reference when
> triaging your own server logs.

---

## 2. The four stages — trace, detection rule, and correct WAF response

This is the summary. Each stage is detailed below.

| Stage | What it looks like in the log | **WAF end goal** | How to know it is correct |
|-------|-------------------------------|------------------|---------------------------|
| **1. Passive recon** | Plain `GET /`, `HEAD /` collecting `Server:` / `X-Powered-By:` version tokens | **Deny information** (scrub banners) — do NOT block. A `GET /` is legitimate. | No version/OS/OpenSSL token remains in the response. The attacker learns no version. |
| **2. Active recon** | Scanner User-Agents (`nuclei`, `whatweb`, `nikto`…), probing `/.env`, `/server-status`, 404 bursts | **Block + alert** the noisy tooling; rate-limit | Scanner-UA/odd-path requests = `403`; an ordinary `control` request = `200`. |
| **3. Exploitation** | `multipart/form-data` POST containing the literal `PHP_SESSION_UPLOAD_PROGRESS` + an oversized field | **Block the attack shape before it reaches PHP** — while allowing real uploads | The `sig` probe = blocked; a real upload + the `control` = `200`; **identical on all three versions**. |
| **4. Post-exploitation** | Apache worker segfaults; `www-data` making outbound connections or writing new `.php` files | **Detect + contain** (a WAF alone cannot — this needs egress control + file/process monitoring) | Any `www-data` egress, new webshell, or Apache `signal 11` raises an alert. |

**Mental model of the correct response:**
*Recon = stop them from learning. Exploitation = stop them from getting in.
Post-exploitation = find out fast and contain it if they are already in.*

---

### Stage 1 — PASSIVE RECON  ·  Goal: **Deny information**

**What it is:** The attacker merely reads the banners — no "attack", just a plain
GET. The problem here is the **fingerprint leak** itself.

**Trace in `lab_capture.log`:** a series of `GET /` / `HEAD /` from a single IP whose
**response** carries:
```
Server: Apache/2.4.x (Debian) OpenSSL/3.x.x PHP/8.0.30
X-Powered-By: PHP/8.0.30
```
(The lab leaks this on purpose, so you can see exactly what recon obtains.)

**Detection one-liner** (run on your host):
```bash
# which version tokens is each host currently leaking?
grep -iE 'Server:|X-Powered-By:' logs/*/lab_capture.log | sort -u
```

**WAF/edge end goal — SCRUB, do not block:**
- `ServerTokens Prod` + `ServerSignature Off` (Apache) → `Server: Apache` only.
- `Header always unset X-Powered-By` / `expose_php = Off` (PHP) → remove the PHP token.
- Alert on **version enumeration** (many HEAD/GET requests doing nothing else).

**It is correct when:** a `GET /` still returns `200` (that is legitimate), but the
attacker can **no longer obtain the version**. This is **hardening**, not blocking —
do not block a simple GET of the homepage.

---

### Stage 2 — ACTIVE RECON  ·  Goal: **Block the noise + alert**

**What it is:** The attacker now uses a scanner — with a recognizable User-Agent —
and probes sensitive paths.

**Trace in `lab_capture.log`:**
- `ua="nuclei/..."`, `ua="whatweb/..."`, `ua="...vuln-checker..."`, or an **empty** UA (`ua="-"`) on a POST.
- Hits on `GET /.env`, `/server-status`, `/assess.php?format=json`.
- Many distinct paths in a short window (404 burst) from one source.

**Detection one-liners:**
```bash
# known scanner User-Agents
grep -iE 'ua="[^"]*(nuclei|whatweb|nikto|sqlmap|zgrab|masscan|nmap|vuln-checker)' logs/*/lab_capture.log

# probing of sensitive paths
grep -E '"(GET|POST) /(\.env|server-status|\.git)' logs/*/lab_capture.log

# 404 burst from one IP (an enumeration signal)
awk '$NF ~ /404/ {print $1}' logs/*/lab_capture.log | sort | uniq -c | sort -rn | head
```

**WAF end goal — block + alert:**
- Block known scanner UAs → rule **`1000200`** (`deny,status:403`).
- Flag requests with no UA → rule **`1000210`** (log first, before blocking).
- Rate/anomaly limit sources issuing many distinct paths.

**It is correct when:** scanner-UA and `.env` probes return `403` (or reset), while an
ordinary browser request (`control`) still returns `200`. **Caveat:** a real adversary
can trivially forge the UA — this only removes noisy public tooling, not a targeted
attacker. Stage 3 is therefore still required.

---

### Stage 3 — EXPLOITATION  ·  Goal: **Block the attack shape**

**This is the strongest and most important signature.** The PHP2Shell trigger is a
**`multipart/form-data` POST containing a `PHP_SESSION_UPLOAD_PROGRESS` field**
(often with an oversized field to drive the memory/OOM chain).

**Trace in `lab_capture.log`:**
```
"POST /index.php HTTP/1.1" 200 .. ct="multipart/form-data; boundary=..." len=65611 ua="-"
```
→ `ct="multipart/form-data"` + a large `len=` + (in `error.log`/dumpio body) the
literal string `PHP_SESSION_UPLOAD_PROGRESS`.

**Detection one-liners:**
```bash
# all multipart POSTs (the trigger content type)
grep -E 'ct="multipart/form-data' logs/*/lab_capture.log

# the core IOC: the literal field name (requires dumpio body capture)
grep -i 'PHP_SESSION_UPLOAD_PROGRESS' logs/*/error.log

# abnormally large request body (OOM / oversized-field attempt)
awk -F'len=' '$2+0 > 1000000 {print FILENAME": "$0}' logs/*/lab_capture.log
```

**Did it reach the vulnerable code path (not just a probe)?** Check `error.log` for
**memory exhaustion / worker crash** — the "tell" that the bug was actually reached,
not merely shaped:
```bash
grep -iE 'Allowed memory size .* exhausted|child pid [0-9]+ exit signal Segmentation fault \(11\)|signal 11' logs/*/error.log
```

**WAF end goal — block the shape before it reaches PHP, while allowing real uploads:**
- Detect multipart POSTs → rule **`1000100`** (always logs).
- Allow-list your real upload routes → rule **`1000090`** *(do this first).*
- Then block multipart on **non-upload** paths → rule **`1000110`**
  (change `pass` → `deny,status:403`).
- Flag/block `PHP_SESSION_UPLOAD_PROGRESS` → rule **`1000120`**.
- Flag oversized field/field-name → rules **`1000130` / `1000131`**.

**It is correct when (all three must hold):**
1. the `sig` / exploitation-shape probe is **blocked** (`403`/reset),
2. a real upload to an allow-listed route **and** the `control` GET both return **`200`**,
3. the behavior is **identical across all three versions** (`:8080`, `:8081`,
   `:8082`) — meaning you are targeting the **attack shape**, not "any PHP server".

---

### Stage 4 — POST-EXPLOITATION  ·  Goal: **Detect + contain**

If something gets through (RCE achieved), a WAF can no longer stop it — now the goal
is **fast detection + containment**. (This lab does not simulate this stage — it ships
no exploit — but these are the signals to monitor on a real host.)

**Signals to watch for:**
- **Apache worker crash-respawn** in `error.log` (`signal 11` / segfault) occurring
  repeatedly — the UAF/OOM being driven.
- **A new or modified `.php` file** in the webroot (webshell drop). In the lab the
  mount is `:ro` (read-only), so a **write attempt itself** is an IOC.
- **An outbound connection from `www-data`** (reverse shell / C2). The lab should have
  no egress — any outbound connection is a compromise.
- **A child process spawned by Apache/PHP:** `sh`, `bash`, `nc`, `curl`, `wget`, or
  `python` whose parent is `apache2` / `php-fpm`.
- **`sess_*` files in `/tmp`** containing embedded PHP/serialized payloads, or a sudden
  growth of `/tmp`.
- **Log gaps / truncation** — if `lab_capture.log` suddenly stops, that itself is a
  signal (detection evasion).

**End goal (defense-in-depth — not the WAF alone):**
- **Egress control** — block outbound from the web host; alert on every attempt.
- **File Integrity Monitoring (FIM)** on the webroot — alert on any new `.php`.
- **Process monitoring** — alert on a shell/network child of `apache2`/`php-fpm`.
- **Containment** — isolate the host, preserve `logs/` for forensics, then **patch PHP**
  (the real fix).

**It is correct when:** you are alerted on the *first* `www-data` egress or webshell
write — not days later.

---

## 3. The detection rules, in one table

All rules live in [`waf/php2shell-virtual-patch.conf`](../waf/php2shell-virtual-patch.conf)
(ModSecurity / SecLang). This is the map:

| Rule ID | What it catches | Default action | Stage |
|---------|-----------------|----------------|-------|
| `1000090` | Allow-list of real upload routes (so they are not blocked) | `pass` (skip 1000110) | 3 (setup) |
| `1000100` | `multipart/form-data` POST to PHP | `log` | 3 |
| `1000110` | Multipart on a **non-upload** path | `pass` → change to `deny` | 3 |
| `1000120` | `PHP_SESSION_UPLOAD_PROGRESS` in the body | `log` | 3 |
| `1000130` / `131` | Oversized field value (>2MB) / field name (>1KB) | `log` | 3 |
| `1000140` | POST with no usable `Content-Length` but a large body | `log` | 3 |
| `1000200` | Known scanner User-Agent | `deny,status:403` | 2 |
| `1000210` | No User-Agent | `log` (before blocking) | 2 |

> **Note:** most rules are `log`-only at first. That is intentional — observe which
> **legitimate** traffic matches before you enable blocking. See the
> "DetectionOnly → allow-list → block" workflow in [`docs/waf-tuning.md`](../docs/waf-tuning.md).

---

## 4. The `scan/*.sh` scripts — what to run and the expected output

Every script is **benign** (no exploit). Each sends requests to the three lab hosts
and compares them. Run from the repository root.

> **Two ways to run:**
> - **Directly at the lab** (no WAF) → this is the **baseline**. All `200`.
> - **Through a WAF** (`TARGET=http://your-waf ...`) → this is where you see the block.
> The difference between the two is the **proof** that your rule works.

### `check.sh` — "is the lab up and is the verdict correct?"
```bash
bash scan/check.sh
```
Expected:
```
ROLE       PORT   PHP        STATUS           FIXED-IN
-----------------------------------------------------------------
EOL        8080   8.0.30     EOL_UNSUPPORTED  none (EOL)
OUTDATED   8081   8.4.26     VULNERABLE       8.4.27
PATCHED    8082   8.4.27     PATCHED          8.4.27
```
`UNREACHABLE` → the lab is not up (run `bash setup.sh` first).

### `profile.sh verify` — "is the fingerprint real, not spoofed?"
```bash
bash scan/profile.sh verify
```
Expected: all `[PASS]`, ending in:
```
RESULT: N passed, 0 failed, 0 skipped
=> Fingerprint is REAL: headers come from the live Apache/PHP/OpenSSL runtime, not faked.
```
A `[FAIL]` on the banner/OpenSSL token → the fingerprint config of that image is
wrong (this is exactly what a broken `eol` Dockerfile without `ServerTokens Full`
would cause). `[SKIP]` = no Docker available (HTTP checks ran only).

### `profile.sh` — "what is the per-version behavior? (false-positive baseline)"
```bash
bash scan/profile.sh
```
Prints the Server/X-Powered-By/`PHPSESSID` shape + status/timing of ordinary requests
per host. This is your **baseline**: whatever a WAF rule does to the `sig` probe, it
**must not touch these**.

### `wafprobe.sh sig` — "does the WAF block the detection signature?"
```bash
# baseline (directly at the lab):
bash scan/wafprobe.sh sig
# through a WAF:
TARGET=http://your-waf bash scan/wafprobe.sh sig
```
Each probe prints the **actual request** (line, headers, body — the multipart body
is where you can read the literal `PHP_SESSION_UPLOAD_PROGRESS` detection string),
the **actual response** (status + `Server`/`X-Powered-By`/`Content-Type` + a body
snippet), and a per-probe `CURRENT | EXPECTED` line. Example `sig` probe:
```
  -- [sig] POST multipart + UPLOAD_PROGRESS
     REQUEST : POST /index.php HTTP/1.1
               Content-Type: multipart/form-data; boundary=------------------------xxxx
               Content-Length: 419
               body:
                 | --------------------------xxxx
                 | Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"
                 |
                 | wafprobe-20261023T....Z
                 | --------------------------xxxx ...
     RESPONSE: HTTP/1.1 200 OK
               Server: Apache/2.4.x (Debian) OpenSSL/3.x PHP/8.4.26
               X-Powered-By: PHP/8.4.26
               body: OK
     CURRENT : HTTP 200   |   EXPECTED (tuned WAF): HTTP 403 / reset — block
```
Each target ends with the **summary table** — the whole point: current state vs.
the response a tuned WAF should give.
```
  SUMMARY — current vs. expected (tuned WAF)
  PROBE         REQUEST SHAPE                      CURRENT      EXPECTED
  ------------------------------------------------------------------------------
  control       GET / (ordinary)                   HTTP 200     HTTP 200 — legit, must pass
  sig           POST multipart + UPLOAD_PROGRESS   HTTP 200     HTTP 403 / reset — block
  sig-name      POST upload_progress_<marker> field HTTP 200    HTTP 403 / reset — block
```
**Baseline, no WAF:** every `CURRENT` is `HTTP 200` — that is the current state, not
a pass/fail. **Behind a tuned WAF:** drive each `sig`/`sig-name` `CURRENT` to its
`EXPECTED` (403/reset) while `control` stays `200`. A `control` that becomes `403` =
**too strict** (false positive) — review the allow-list.

### `wafprobe.sh stages` — "is it blocked at EVERY stage?"
```bash
TARGET=http://your-waf bash scan/wafprobe.sh stages
```
Same per-probe request/response detail as `sig`, grouped into the three stages,
each target ending with the summary table. Expected behind a tuned WAF:
```
[1] passive  -> Server/X-Powered-By SCRUBBED (blank), enumeration alerted
[2] active   -> scanner-UA requests = HTTP 403; "control" = HTTP 200
[3] exploit  -> multipart / PHP_SESSION_UPLOAD_PROGRESS / oversized = HTTP 403;
                "control" GET = HTTP 200
```
Directly at the lab (no WAF) every `CURRENT` is `200`/leaky = baseline (not a
pass/fail); behind the WAF each `CURRENT` should match its `EXPECTED`.

> **Confirm in the logs:** each script prints a unique `Marker:` string. Grep for it in
> `logs/<role>/lab_capture.log` to prove the probe reached the app (and to see what was
> captured) — this is the continuous feedback loop of detection engineering.

---

## 5. The golden rule (false-positive discipline)

The most common beginner mistake is to **block everything immediately**. A bad rule
that blocks legitimate traffic is more dangerous than no rule — your team will turn it
off, and then you have no protection.

1. **DetectionOnly first.** Log before blocking. See who matches.
2. **Allow-list the legitimate.** Your real upload routes (rule `1000090`) before you
   enable the block (`1000110`).
3. **Verify across three versions.** The rule must behave identically on
   `:8080/:8081/:8082`. If it differs from the patched host (`:8082`), you are
   targeting "PHP", not the attack.
4. **Re-check the `control`.** In every test, the ordinary request must still return
   `200`. That is your "I am not breaking anything" proof.

---

## 6. Honest scope (do not fool yourself with your own rules)

- A WAF is a **stopgap**. The bug runs inside PHP before the application code — the
  only complete fix is to **upgrade** (`8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`, or a vendor
  backport for EOL branches such as `8.0`).
- Detection + rules only reduce **exposure** and give you **visibility + time** — they
  do not fix the bug.
- The User-Agent is easily forged; the attacker can vary the shape of the attack. The
  defense must therefore be **layered** — recon-scrub + UA-block + shape-block +
  post-exploitation monitoring — not a single rule.
- Track every host that is still only WAF-shielded, and upgrade it as soon as possible.

**Sources:** [Datadog Security Labs][dd] · [Sansec][ss]

[dd]: https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
[ss]: https://sansec.io/research/php2shell

---

## 7. Appendix — App-layer chain: LFI + session fixation

> This appendix covers the two **application** vulnerabilities added to the lab app
> (`webapp/view.php`, `webapp/login.php`). They are independent of the PHP2Shell
> runtime bug — present on patched and unpatched hosts alike — and fixed in code, not
> by upgrading PHP. Remediation: [`docs/lfi-remediation.md`](../docs/lfi-remediation.md),
> [`docs/session-fixation-remediation.md`](../docs/session-fixation-remediation.md).
> Rules: [`waf/lfi-virtual-patch.conf`](../waf/lfi-virtual-patch.conf) (IDs `1000300`–`1000350`).
> Sample capture: [`scan/sample-logs/lfi-access.log`](sample-logs/lfi-access.log).

### What it is (plain terms)

| Term | In plain terms |
|------|----------------|
| **LFI** (Local File Inclusion) | The app hands user input to `include()`. The attacker steers it to read, or **execute**, files on the server. |
| **Session fixation** | The app lets the attacker choose the session id and keeps it valid after login — so the attacker rides the victim's authenticated session, and the session file sits at a predictable path. |
| **The chain** | fixation gives a known `/tmp/sess_<id>` path → poison it with PHP → LFI `include()`s it → **RCE**, with no remote file fetch needed. |

### How to read it in the logs

Look at the `doc` parameter on `/view.php`. In normal use it is an article name
(`welcome.php`). It is an **attack** when it contains any of:

1. **Traversal** — `../` runs or encoded forms (`%2e%2e%2f`). → WAF `1000300`.
2. **Stream wrapper** — `php://`, `data://`, `phar://`. → WAF `1000310`.
3. **Sensitive absolute path** — `/etc/passwd`, `/var/log/…`, `/tmp/sess_…`. → WAF `1000320`.
4. **`?sid=` on `/login.php`** — a caller-supplied session id (fixation). → WAF `1000340`.

A single client showing **two or more** of these (e.g. `1000340` then `1000320`) is the
combined chain assembling — rule `1000350` escalates on the correlated score. Walk
[`sample-logs/lfi-access.log`](sample-logs/lfi-access.log) stage by stage to see it.

### What the correct WAF response is (the end goal)

| Stage | Trace | Correct response |
|-------|-------|------------------|
| LFI probe | `doc` with `../` or `php://` | **403** at the edge (`1000300`/`1000310`) + alert |
| Sensitive path | `doc=…/etc/passwd`, `…/tmp/sess_…` | **403** (`1000320`) + alert |
| Fixation | `/login.php?sid=…` | **403** (`1000340`) — the app should never take an id from the URL |
| Chain assembling | two+ indicators, one client | escalate (`1000350`); block the client |

### Honest scope (same caveat as §6)

The WAF is a **stopgap**. The real fix is the code change: allow-list + `basename()` +
`realpath()` in `view.php`, and `session_regenerate_id(true)` + `use_strict_mode=1` in
`login.php`. Remove `waf/lfi-virtual-patch.conf` once those ship. Verify by re-running
the probes in `lfi-access.log`: fixed, they return **404/normal**, not file contents.
