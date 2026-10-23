# Session Fixation — Impact & Remediation Report

**Vulnerability:** Session Fixation (CWE-384)
**Location:** `webapp/login.php` — the Member login flow
**Prepared for:** app-security / remediation-owner audience
**Lab:** app-layer flaw that chains with the Knowledge-Base LFI (`docs/lfi-remediation.md`)

---

## 1. Summary

The login flow lets an attacker **choose the session identifier** and keeps that identifier valid
**across authentication**. Two real-world default mistakes, both present:

```php
if (isset($_GET['sid']) && $_GET['sid'] !== '') {
    session_id($_GET['sid']);   // (1) adopt a caller-supplied id
}
session_start();
// ... on successful login:
$_SESSION['user'] = 'employee'; // (2) no session_regenerate_id(true) on privilege change
```

With `session.use_strict_mode=0` (PHP's historical default, left as-is here for fidelity) an unknown,
attacker-chosen id is accepted and its server-side file is created at a **predictable** path
(`/tmp/sess_<id>`).

## 2. How it is exploited (this lab)

**Classic fixation:**
1. Attacker picks an id, e.g. `AAAA1111`, and primes it: `GET /login.php?sid=AAAA1111`.
2. Attacker sends the victim the same link `…/login.php?sid=AAAA1111`.
3. Victim signs in. Because the id is not regenerated, session `AAAA1111` is now an **authenticated**
   session the attacker also holds → account takeover.

**Combined with the LFI (fixation → RCE):** the predictable session-file path is the bridge to the
`include()` sink in `view.php`:

```
GET /login.php?sid=shellsess        # create /tmp/sess_shellsess
POST /login.php  note=<?php system($_GET['c']); ?>   # write PHP into the session file
GET /view.php?doc=../../../../tmp/sess_shellsess&c=id   # LFI include() executes it -> RCE
```

This works even with `allow_url_include=Off` — every read is local. It is the reason session fixation
and LFI are documented together: either bug is serious; **together they are a self-contained RCE**.

## 3. Impact

- **Account takeover:** attacker rides the victim's authenticated session.
- **RCE (combined):** the attacker-controlled, predictably-named session file becomes the payload the
  LFI executes.
- Independent of the PHP2Shell runtime bug — present on patched and unpatched hosts alike until the
  app is fixed.

## 4. Remediation (the fix)

```php
// 1. Never adopt a caller-supplied id. Delete the ?sid= handling entirely.
//    (no session_id($_GET['sid']);)

// 2. Harden the cookie + reject uninitialised ids at the engine level.
ini_set('session.use_strict_mode', '1');   // ignore ids the server never issued
ini_set('session.use_only_cookies', '1');  // never read the id from the URL
session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);
session_start();

// 3. Regenerate the id on every privilege change (login, logout, role change).
if ($login_ok) {
    session_regenerate_id(true);   // new id; old session file deleted
    $_SESSION['user'] = 'employee';
}
```

Controls, strongest first:

1. **`session_regenerate_id(true)` on login** — the single control that defeats fixation; the
   pre-auth id the attacker fixed is discarded.
2. **`session.use_strict_mode=1`** — the engine refuses any id it did not generate, so a primed id is
   never accepted in the first place.
3. **`session.use_only_cookies=1`** and **remove `?sid=` handling** — the id can no longer be carried
   or set via the URL.
4. **Harden the cookie**: `HttpOnly`, `Secure`, `SameSite` — shrinks the ways an id gets fixed (XSS,
   cross-site).
5. **Don't store attacker-controlled raw input in the session** and keep session files out of any
   `include()` reach — this also severs the combined chain (see `docs/lfi-remediation.md`).

## 5. Verification

- `GET /login.php?sid=AAAA1111` then sign in → session id **changes** after login (regenerated).
- `session.use_strict_mode=1` → a never-issued id is replaced, not adopted.
- The combined chain fails: even if a session file is poisoned, the fixed `view.php` allow-list
  refuses `?doc=../../../../tmp/sess_…`.
- Detection traces: `scan/DETECTION.md` (session-fixation + LFI section).
