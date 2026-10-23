<?php
/**
 * "Member login" for the Acme Intranet Portal.
 *
 * LAB — VULNERABLE BY DESIGN (Session Fixation, CWE-384).
 * ----------------------------------------------------------------------------
 * Two deliberate flaws, both the real-world default mistakes:
 *
 *   1. The app ADOPTS a caller-supplied session id (?sid=...) before the
 *      session starts. An attacker can therefore pin a session id they already
 *      know and hand the victim a link to it.
 *   2. The id is NOT regenerated on privilege change (no session_regenerate_id()
 *      after a successful login). So the pre-auth id the attacker fixed stays
 *      valid AFTER the victim authenticates.
 *
 * With session.use_strict_mode=0 (PHP's historical default — left as-is here for
 * fidelity) an unknown, attacker-chosen id is accepted and its file is created
 * at a PREDICTABLE path (/tmp/sess_<id>). That is what links this to the LFI:
 *
 *     fixation  -> attacker knows /tmp/sess_<id>
 *     poison    -> write PHP into the session (e.g. via a stored field)
 *     LFI       -> /view.php?doc=../../../../tmp/sess_<id>  ->  include() runs it  ->  RCE
 *
 * Remediation: docs/session-fixation-remediation.md.
 */
require __DIR__ . '/includes/layout.php';

// --- VULNERABLE: honour a caller-supplied session id --------------------------
if (isset($_GET['sid']) && $_GET['sid'] !== '') {
    session_id($_GET['sid']);          // adopt attacker-chosen id (fixation sink #1)
}
session_start();
// -----------------------------------------------------------------------------

$error = null;
if (($_POST['action'] ?? '') === 'login') {
    // Lab credentials — the point is the session handling, not the auth.
    if (($_POST['user'] ?? '') === 'employee' && ($_POST['pass'] ?? '') === 'acme123') {
        // VULNERABLE: no session_regenerate_id(true) here (fixation sink #2).
        $_SESSION['user'] = 'employee';
        $_SESSION['note'] = $_POST['note'] ?? '';   // attacker-writable session field
    } else {
        $error = 'Invalid credentials. Try employee / acme123.';
    }
}
if (($_GET['action'] ?? '') === 'logout') {
    $_SESSION = [];
}

render_header('Member Login');
?>
<section class="panel">
  <h3>Member login</h3>
  <p class="muted">Session id for this request: <code><?= htmlspecialchars(session_id()) ?></code></p>

  <?php if (!empty($_SESSION['user'])): ?>
    <p>Signed in as <strong><?= htmlspecialchars($_SESSION['user']) ?></strong>.
       Note on file: <code><?= htmlspecialchars($_SESSION['note'] ?? '') ?></code></p>
    <p><a class="btn" href="/login.php?action=logout">Sign out</a></p>
  <?php else: ?>
    <?php if ($error): ?><p class="reason"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <form method="post" action="/login.php">
      <input type="hidden" name="action" value="login">
      <p><label>User<br><input name="user" value="employee"></label></p>
      <p><label>Password<br><input name="pass" type="password" value="acme123"></label></p>
      <p><label>Status note<br><input name="note" placeholder="optional"></label></p>
      <p><button class="btn" type="submit">Sign in</button></p>
    </form>
  <?php endif; ?>
</section>

<section class="panel">
  <p class="muted"><strong>LAB:</strong> deliberate session fixation. The id persists across login and
     can be pre-set via <code>?sid=&lt;id&gt;</code>. Paired with the Knowledge-Base LFI it forms a
     session-file &rarr; <code>include()</code> &rarr; RCE chain. Remediation:
     <code>docs/session-fixation-remediation.md</code>.</p>
</section>
<?php
render_footer();
