# PHP2Shell — Impact & Remediation Report

**Vulnerability:** PHP2Shell — CVE-2026-109618 & CVE-2026-109619
**Disclosed:** 2026-10-21 · **Severity:** CVSS v4.0 **9.2** (both) · **Auth:** none required
**Prepared for:** patch-management / risk-owner audience
**Lab:** three-version Docker matrix in this repository

---

## 1. Summary

Two critical memory-corruption vulnerabilities in the PHP runtime allow an **unauthenticated**
attacker to achieve **remote code execution** against a web server running an affected PHP build.
Both are triggered **before application code runs**, so no vulnerable application logic is required —
any site on an affected runtime is exposed. PHP rates the risk **highest for Apache `mod_php`**.

| CVE | Root cause | Impact |
|-----|-----------|--------|
| CVE-2026-109618 | Out-of-memory corruption during request cleanup | Unauth RCE |
| CVE-2026-109619 | Stale request-owned global state reused by a later request on the same worker | Unauth RCE |

## 2. Affected & fixed versions

- **Fixed releases (2026-10-21):** PHP **8.5.12**, **8.4.27**, **8.3.36**, **8.2.35**.
- **Affected:** every release older than the fix on its branch.
- **End-of-life (8.1 and earlier):** no upstream fix. Rely on distribution backports (e.g. the
  minimal source backports referenced for 7.4 / 8.0 / 8.1) or migrate to a supported branch.
- **Affected SAPIs:** `mod_php` (highest risk), PHP-FPM, php-cgi, FrankenPHP, LiteSpeed.

## 3. Demonstrated exposure (this lab)

The lab serves one identical web application on three real PHP runtimes. Scanner output
(`bash scan/check.sh`) produces evidence of the form:

```
ROLE       PORT   PHP        STATUS           FIXED-IN
-----------------------------------------------------------------
EOL        8080   8.0.x      EOL_UNSUPPORTED  none (EOL)
OUTDATED   8081   8.4.26     VULNERABLE       8.4.27
PATCHED    8082   8.4.27     PATCHED          8.4.27
```

- **EOL (8.0) and Outdated (8.4.26)** runtimes are exposed: they run genuinely affected PHP builds
  with no fix applied. Any site served by these runtimes is at risk regardless of its own code.
- **Patched (≥ 8.4.27)** runtime carries the fix and is not exposed.

The three hosts are authentic, production-shaped PHP targets. Their value to a defender is that
firewall / WAF / IDS rules and detection content can be developed against a **real** vulnerable
runtime (its banners, headers, config and error behaviour) and then validated against the patched
baseline to keep false positives down — all in an isolated, never-deployed environment.

> **Note on scope.** The real exploit primitive for these CVEs is not public, and this lab ships
> **no exploit code**. It proves exposure by **version and configuration** — the verifiable facts a
> defender acts on — and exists to stand up real affected runtimes to build and test defenses against.

> _Insert screenshot: `/assess.php` VULNERABLE on :8080 vs PATCHED on :8082, or the `scan/check.sh` table._

## 4. Recommendations (priority order)

1. **Patch the PHP runtime now.** Upgrade to **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** or later on the
   matching branch. **Restart PHP workers / the web server** after upgrading — long-lived workers
   keep the vulnerable code resident until recycled.
2. **Patch the *runtime*, not the app.** Updating WordPress, Drupal, or Laravel does **not** fix
   this — the fix is in the PHP package / container image underneath them.
3. **Inventory bundled PHP.** Check PHP embedded in container images, appliances, and third-party
   products; apply vendor updates as they ship. Consult the NCSC-NL affected-products tracker.
4. **Migrate EOL runtimes.** PHP 8.1 and earlier get no upstream fix. Move to a supported, patched
   branch, or apply a trusted distribution backport as a stopgap.
5. **Interim mitigations (not a substitute for patching).** Per PHP guidance: disable
   `session.upload_progress`, restart workers, and review `memory_limit` / `post_max_size`; on
   PHP 8.5 review `fatal_error_backtraces`. The patched container in this lab applies the
   `session.upload_progress` mitigation as defense-in-depth.
6. **Detect & monitor.** Watch internet-facing web/app logs and vendor advisories for exploitation
   activity; exploitation attempts were observed around disclosure.

## 5. References

- NCSC-NL php2shell tracker — <https://github.com/NCSC-NL/php2shell>
- watchTowr FAQ — <https://watchtowr.com/intelligence/php-cve-2026-109618-faq/>
- Help Net Security — <https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/>
- The Hacker News — <https://thehackernews.com/2026/10/php2shell-two-unpatched-critical-php.html>
- Security.com — <https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619>
