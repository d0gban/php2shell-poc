<?php
require __DIR__ . '/includes/cve.php';
require __DIR__ . '/includes/layout.php';

$verdict = php2shell_verdict(PHP_VERSION);
$sapi    = php2shell_sapi_context();
$vulnerable = in_array($verdict['status'], ['VULNERABLE', 'EOL_UNSUPPORTED'], true);

render_header('Home');
?>
<section class="hero">
  <h1>Acme Intranet Portal</h1>
  <p class="lede">Internal tools &amp; document hub. This simple app is the hosted workload — the
  point of interest for this lab is the <em>PHP runtime underneath it</em>. Each lab host serves the
  same app on a different PHP build, giving blue teams a real, production-shaped PHP target to profile
  and to tune firewall / WAF / detection rules against — without touching anything in production.</p>
</section>

<section class="statuscard <?= $vulnerable ? 'is-bad' : 'is-good' ?>">
  <div class="statuscard-head">
    <h2>PHP2Shell exposure</h2>
    <?= badge($verdict['status']) ?>
  </div>
  <dl class="kv">
    <dt>Running PHP</dt><dd><?= htmlspecialchars($verdict['running']) ?> (branch <?= htmlspecialchars($verdict['branch']) ?>)</dd>
    <dt>Fixed in</dt><dd><?= htmlspecialchars($verdict['fixed_in'] ?? 'no upstream fix (EOL)') ?></dd>
    <dt>SAPI</dt><dd><?= htmlspecialchars($sapi['note']) ?></dd>
    <dt>CVEs</dt><dd><?= htmlspecialchars(implode(' · ', $verdict['cves'])) ?></dd>
  </dl>
  <p class="reason"><?= htmlspecialchars($verdict['reason']) ?></p>
  <p><a class="btn" href="/assess.php">Run full self-assessment →</a></p>
  <?php if ($vulnerable): ?>
  <p class="impact-link">⚠ This runtime is a genuinely affected PHP build on
     <code>http://localhost:<?= htmlspecialchars((string)($_SERVER['SERVER_PORT'] ?? '')) ?></code>.
     Use it as a reference target when profiling the server fingerprint and validating firewall / WAF
     and detection rules for PHP2Shell.</p>
  <?php else: ?>
  <p class="impact-link ok">✓ This runtime carries the PHP2Shell fix — use it as the patched baseline
     to confirm your rules don't flag an already-remediated host.</p>
  <?php endif; ?>
</section>
<?php
render_footer();
