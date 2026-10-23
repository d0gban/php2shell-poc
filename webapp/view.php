<?php
/**
 * Knowledge-base document viewer for the Acme Intranet Portal.
 *
 * LAB — VULNERABLE BY DESIGN (Local File Inclusion, CWE-98 / CWE-22).
 * ----------------------------------------------------------------------------
 * This page is the concrete demonstration of the first app-code precondition
 * that the PHP2Shell self-check (/assess.php) warns about:
 *
 *     "an include()/require() sink reachable with attacker-influenced input (LFI)"
 *
 * The `doc` parameter is passed straight into include() with no allow-list,
 * no basename(), no realpath() containment and no scheme filtering. That is a
 * textbook LFI: path traversal reads arbitrary files, php:// wrappers disclose
 * source, and an includable attacker-controlled file (poisoned log, uploaded
 * content, session file) turns the same sink into remote code execution.
 *
 * On a runtime that is ALSO affected by PHP2Shell, this include sink is exactly
 * the application-layer half that completes the chain. Fixing it (see
 * docs/lfi-remediation.md) removes the LFI independently of the PHP patch.
 *
 * DO NOT copy this pattern into real code. See the remediation doc for the
 * allow-list / basename / realpath fix.
 */
require __DIR__ . '/includes/layout.php';

$docs_dir = __DIR__ . '/content/';
$doc      = $_GET['doc'] ?? 'welcome.php';   // internal links pass the file name

render_header('Knowledge Base');
?>
<section class="panel">
  <div class="kb">
    <nav class="kb-nav" aria-label="Articles">
      <h3>Articles</h3>
      <ul>
        <li><a href="/view.php?doc=welcome.php">Welcome</a></li>
        <li><a href="/view.php?doc=onboarding.php">New-starter onboarding</a></li>
      </ul>
      <p class="muted">Viewer: <code>/view.php?doc=&lt;name&gt;</code></p>
    </nav>
    <article class="kb-body">
<?php
      // --- VULNERABLE SINK --------------------------------------------------
      // User input flows directly into include(). No containment of any kind.
      include $docs_dir . $doc;
      // ----------------------------------------------------------------------
?>
    </article>
  </div>
</section>

<section class="panel">
  <p class="muted"><strong>LAB:</strong> this viewer contains a deliberate Local File Inclusion.
     It exists to profile LFI request/response traces and to validate WAF and detection rules
     against a real sink — see <code>scan/DETECTION.md</code> and
     <code>waf/lfi-virtual-patch.conf</code>. Remediation: <code>docs/lfi-remediation.md</code>.</p>
</section>
<?php
render_footer();
