# PHP2Shell — WAF tuning & virtual patching for hosts that can't upgrade

**For:** blue teams shielding webapps that cannot immediately upgrade PHP
(CVE-2026-109618 / CVE-2026-109619).
**Reminder:** a WAF is a *stopgap*. Both PHP2Shell flaws execute **inside PHP,
before application code**, so WAF/virtual-patching is defense-in-depth — the only
complete fix is upgrading to **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** (or a vendor
backport for EOL branches). Sources: [Datadog Security Labs][dd], [Sansec][ss].

## Why "curl returns the PHP version" isn't enough

Version detection tells you *which hosts are exposed*; it does nothing for a WAF.
A WAF matches **HTTP** — request shape, headers, body bytes, field names, cookie
shape — never the memory bug itself. So tuning needs **attack-shaped traffic**
and a **per-version behaviour baseline**, both of which this lab gives you
without any exploit:

| You need | Use | What it is |
|----------|-----|------------|
| Attack-shaped (but inert) traffic | [`scan/waf-test.sh`](../scan/waf-test.sh) | Benign multipart probes carrying the `PHP_SESSION_UPLOAD_PROGRESS` detection signature. No primitive, no RCE. |
| Per-version HTTP behaviour | [`scan/behavior.sh`](../scan/behavior.sh) | Banners, headers, PHPSESSID shape, status/timing for ordinary requests — your false-positive baseline. |
| Virtual-patch rules | [`waf/php2shell-virtual-patch.conf`](../waf/php2shell-virtual-patch.conf) | ModSecurity rules keyed on the public HTTP IOCs. |

## HTTP-level indicators (from the public advisories)

- **`multipart/form-data` POSTs to PHP** — Sansec: *every known trigger* uses this
  content type. Highest-signal, highest false-positive (real uploads use it too).
- **`PHP_SESSION_UPLOAD_PROGRESS`** field — the `session.upload_progress` vector
  (CVE-2026-109619).
- **Oversized bodies / a single multi-MB field, or abnormally long field names**
  (incl. nested `name[x]=`), and **empty-name fields with control/null bytes**.
- **POSTs with no usable `Content-Length`** that still decode to a large body.
- **Abnormal `PHPSESSID` response cookie** (long/odd) — memory disclosure path of
  CVE-2026-109619.
- Make sure your inspection engine **doesn't truncate large bodies** — a rule
  can't match bytes it never receives.

## Tuning workflow

1. **Baseline, no WAF:** `bash scan/behavior.sh` and `bash scan/waf-test.sh`
   straight at the lab ports. Record status/timing — "sig" and "control" both 200.
2. **Put your WAF in front** (`TARGET=http://your-waf bash scan/waf-test.sh`).
3. **Load** `waf/php2shell-virtual-patch.conf` in **DetectionOnly** first. Watch
   which legitimate traffic rule 1000100 lights up.
4. **Allow-list** real upload routes (rule 1000090), then flip the non-upload
   block (1000110) to `deny,status:403`.
5. **Verify:** the "sig"/"sig-name" probes get blocked; `behavior.sh`'s ordinary
   requests and your real app traffic stay 200. Confirm the same on all three
   PHP versions — a good rule targets the *attack shape*, not "any PHP server".

## PHP config mitigations (apply alongside the WAF)

Loaded **before request parsing**, then **restart all workers** (per-pool in
PHP-FPM). Partial — pair them, don't rely on any one:

- `session.upload_progress.enabled = 0` — addresses the CVE-2026-109619 vector.
  (The lab's `/assess.php` already reports this setting's live value.)
- `fatal_error_backtraces = 0` — on PHP 8.5, for CVE-2026-109619.
- `memory_limit = -1` at the **admin** level, **paired with** a reverse-proxy
  decoded-body-size limit and a container memory limit. Do **not** set
  `RLIMIT_AS` / `RLIMIT_DATA` — they can trigger the allocation failure the bug
  depends on.
- **Boundary filtering:** cap decoded body size and reject POSTs lacking a usable
  `Content-Length` at the reverse proxy. CERT-EU also recommends restricting
  public exposure of PHP apps.
- **Last-resort (breaks uploads):** reject `multipart/form-data` to PHP entirely
  at nginx/Apache. Sansec notes this breaks admin image uploads / some checkout
  forms — test an order, and remove it after patching.

## Honest scope

Sansec notes public PoCs reportedly don't work against a default PHP install and
generally need an additional LFI in the app — but treat that as *lower
likelihood, not safety*. These rules reduce exposure; they do not fix the bug.
Track every shielded host and upgrade it as soon as you can.

[dd]: https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
[ss]: https://sansec.io/research/php2shell
