# Sample logs — reference for comparison

**Synthetic, safe-to-share examples** of what each kind of traffic looks like in
the lab's logs. Use them as a **reference** when triaging your own servers: compare
a suspicious line against these to decide *recon vs exploitation vs post-ex*.

> ⚠️ These are **hand-made examples**, not a real capture. All IPs are from the
> documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`,
> RFC 5737) and all markers are obviously benign. Nothing here is an exploit.

| File | What it is | Format |
|------|-----------|--------|
| [`normal-access.log`](normal-access.log) | Clean, legitimate traffic (incl. a **real** multipart upload) | `labcap` access log |
| [`killchain-access.log`](killchain-access.log) | The three attack stages as seen on the **app/access** side | `labcap` access log |
| [`modsec-alerts.log`](modsec-alerts.log) | What the **WAF** writes when the rules fire (per stage/rule) | ModSecurity error-log-style alert |
| [`post-exploitation-error.log`](post-exploitation-error.log) | Server-side **crash evidence** that the bug was actually reached | Apache/PHP `error.log` |

## The `labcap` access-log fields (quick recall)

```
<IP> <ISO8601 time> "<request line>" <status> <bytes> ct="<req Content-Type>" len=<req Content-Length> ua="<User-Agent>" xff="<X-Forwarded-For>"
```

For a plain `GET`, `ct` and `len` are usually `-`. A PHP2Shell exploitation request
stands out as `ct="multipart/form-data..."` with a large `len=`.

## How to use these

1. **Learn the shape.** Read `normal-access.log` first so you know what *boring*
   looks like — that is your baseline.
2. **Match a suspicious line.** Grep your real log and compare to
   `killchain-access.log`:
   ```bash
   # multipart POSTs (the exploitation content type)
   grep -E 'ct="multipart/form-data' /your/access.log
   # the core IOC in WAF/body logs
   grep -i 'PHP_SESSION_UPLOAD_PROGRESS' /your/modsec_audit.log /your/error.log
   # known scanner User-Agents (active recon)
   grep -iE 'ua="[^"]*(nuclei|whatweb|nikto|sqlmap|zgrab|masscan|nmap)' /your/access.log
   ```
3. **Confirm it reached the bug.** If you also see the crash signatures from
   `post-exploitation-error.log` (`Allowed memory size ... exhausted`,
   `exit signal Segmentation fault (11)`) near the same timestamp/worker, treat it
   as **exploitation reaching the vulnerable path**, not just a probe.

See [`../DETECTION.md`](../DETECTION.md) for the full per-stage playbook and the
intended WAF response at each stage.
