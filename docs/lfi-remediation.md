# Local File Inclusion — Impact & Remediation Report

**Vulnerability:** Local File Inclusion (LFI) — CWE-98 (improper control of filename for `include`) / CWE-22 (path traversal)
**Location:** `webapp/view.php` — the Knowledge-Base document viewer
**Prepared for:** app-security / remediation-owner audience
**Lab:** app-layer sink that pairs with the PHP2Shell runtime matrix in this repo

---

## 1. Summary

The document viewer passes the `doc` request parameter straight into `include()` with no
containment:

```php
$doc = $_GET['doc'] ?? 'welcome.php';
include $docs_dir . $doc;          // no allow-list, basename, realpath or scheme check
```

Attacker-controlled input reaching an `include()`/`require()` sink is a **Local File Inclusion**.
Because `include` *executes* PHP in whatever file it resolves, an LFI is not only a file-read bug —
it is a remote-code-execution primitive whenever the attacker can get PHP into any includable file.

This is the concrete form of the first app-code precondition that the PHP2Shell self-check
(`/assess.php`) warns about: *"an `include()`/`require()` sink reachable with attacker-influenced
input (LFI)."* It is an **application** bug and is fixed independently of the PHP runtime patch.

## 2. How it is exploited (this lab)

All probes target the lab viewer on an isolated host. Replace the port with the role under test
(`:8080` EOL · `:8081` outdated · `:8082` patched — the LFI is in the app, so it is present on all three).

| Technique | Request | Result |
|-----------|---------|--------|
| Path traversal / arbitrary read | `/view.php?doc=../../../../etc/passwd` | Non-PHP file contents echoed by `include` |
| Source disclosure (wrapper) | `/view.php?doc=php://filter/convert.base64-encode/resource=../includes/cve.php` | Base64 of app source |
| Log poisoning → RCE | `User-Agent: <?php system($_GET['c']); ?>` then `/view.php?doc=../../../../var/log/apache2/access.log&c=id` | `include()` executes the injected PHP |
| Session-file → RCE (combined) | fix a session (see `session-fixation-remediation.md`), then `/view.php?doc=../../../../tmp/sess_<id>` | `include()` runs PHP stored in the session |

The last row is the **combined chain** with the session-fixation flaw in `webapp/login.php`: it works
even with `allow_url_include=Off`, because every file read is local.

## 3. Impact

- **Confidentiality:** read any file the web user can (`/etc/passwd`, app config, secrets, the PHP
  source itself via `php://filter`).
- **Integrity / availability:** full RCE via log poisoning or the session-file chain — arbitrary
  command execution as the web-server user, i.e. foothold for lateral movement.
- On a runtime **also** affected by PHP2Shell, this is the application half an operator still owns:
  patching PHP closes the memory-corruption RCE; fixing this closes the app-layer RCE. Do both.

## 4. Remediation (the fix)

Resolve user input to a **vetted allow-list**, never to a path. Prefer rendering data over
`include()` for documents.

```php
// 1. Allow-list of renderable articles — the only values ever accepted.
const ARTICLES = ['welcome', 'onboarding'];

$key = $_GET['doc'] ?? 'welcome';
if (!in_array($key, ARTICLES, true)) {
    http_response_code(404);
    exit('Unknown article');
}

// 2. Build the path yourself; strip any directory component defensively.
$path = __DIR__ . '/content/' . basename($key) . '.php';

// 3. Contain to the intended directory with realpath() before use.
$base = realpath(__DIR__ . '/content');
$real = realpath($path);
if ($real === false || !str_starts_with($real, $base . DIRECTORY_SEPARATOR)) {
    http_response_code(404);
    exit('Unknown article');
}
include $real;
```

Layered controls, strongest first:

1. **Allow-list** the finite set of article keys (above). This alone removes the bug.
2. **`basename()`** the input so no directory separators survive.
3. **`realpath()` containment**: resolve and confirm the result stays under `content/`.
4. **Disable stream wrappers** as input: never let `php://`, `data://`, `phar://`, `expect://`
   reach the sink. Set `allow_url_include=Off` (default) and reject any value containing `://`.
5. **Don't `include()` documents at all** where you can avoid it — `readfile()` / templating
   renders content without executing it, removing the RCE class entirely.

### Config-layer backstops (defense-in-depth, not a fix)
- `open_basedir` to jail the PHP process to the web root + required paths — blocks `../` into `/etc`,
  `/tmp`, `/var/log`.
- `allow_url_include=Off`, `allow_url_fopen=Off` where feasible.
- WAF virtual patch: `waf/lfi-virtual-patch.conf` (traversal / wrapper / sensitive-path signatures).
  A stopgap for hosts that cannot ship the code fix yet — remove once `view.php` is fixed.

## 5. Verification

- `/view.php?doc=../../../../etc/passwd` → **404**, no file contents.
- `/view.php?doc=php://filter/...` → **404**, no base64.
- `/view.php?doc=welcome` and `?doc=onboarding` → render normally.
- Detection traces and the expected WAF response: `scan/DETECTION.md` (LFI section) and
  `scan/sample-logs/lfi-access.log`.
