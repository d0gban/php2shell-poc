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
  <p class="lede">Internal tools &amp; document hub. This simple page is the hosted web
  application — the point of interest for this lab is the <em>PHP runtime underneath it</em>.</p>
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
  <p class="impact-link">⚠ This runtime is exposed. See the
     <a href="/lab-impact/foothold.php">simulated post-exploitation impact</a>
     (lab demonstration of what code-execution yields).</p>
  <?php endif; ?>
</section>
<?php
render_footer();
