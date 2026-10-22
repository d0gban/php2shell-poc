<?php
require __DIR__ . '/includes/cve.php';

$verdict     = php2shell_verdict(PHP_VERSION);
$mitigations = php2shell_mitigations();
$sapi        = php2shell_sapi_context();
$vulnerable  = in_array($verdict['status'], ['VULNERABLE', 'EOL_UNSUPPORTED'], true);
$footholdAvailable = is_file(__DIR__ . '/lab-impact/foothold.php');

// Machine-readable output for the host scanner.
if (($_GET['format'] ?? '') === 'json') {
    header('Content-Type: application/json');
    echo json_encode([
        'php_version'         => PHP_VERSION,
        'status'              => $verdict['status'],
        'vulnerable'          => $vulnerable,
        'branch'              => $verdict['branch'],
        'fixed_in'            => $verdict['fixed_in'],
        'cves'                => $verdict['cves'],
        'reason'              => $verdict['reason'],
        'sapi'                => $sapi,
        'mitigations'         => $mitigations,
        'foothold_simulation' => $footholdAvailable,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

require __DIR__ . '/includes/layout.php';
render_header('Security Self-Check');
?>
<section class="statuscard <?= $vulnerable ? 'is-bad' : 'is-good' ?>">
  <div class="statuscard-head">
    <h2>PHP2Shell self-assessment</h2>
    <?= badge($verdict['status']) ?>
  </div>
  <p class="reason"><?= htmlspecialchars($verdict['reason']) ?></p>
  <dl class="kv">
    <dt>Running PHP</dt><dd><?= htmlspecialchars($verdict['running']) ?></dd>
    <dt>Branch</dt><dd><?= htmlspecialchars($verdict['branch']) ?></dd>
    <dt>Fixed release</dt><dd><?= htmlspecialchars($verdict['fixed_in'] ?? 'no upstream fix (EOL branch)') ?></dd>
    <dt>SAPI</dt><dd><?= htmlspecialchars($sapi['note']) ?></dd>
  </dl>
</section>

<section class="panel">
  <h3>Interim mitigation audit</h3>
  <table class="grid">
    <thead><tr><th>Setting</th><th>Current</th><th>Recommended</th><th>State</th></tr></thead>
    <tbody>
    <?php foreach ($mitigations as $m): ?>
      <tr>
        <td><code><?= htmlspecialchars($m['key']) ?></code><br><span class="muted"><?= htmlspecialchars($m['note']) ?></span></td>
        <td><?= htmlspecialchars($m['value']) ?></td>
        <td><?= htmlspecialchars($m['recommended']) ?></td>
        <td><?= $m['ok'] ? '<span class="badge good">OK</span>' : '<span class="badge bad">REVIEW</span>' ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <p class="muted">Mitigations reduce exposure but are <strong>not</strong> a substitute for patching the PHP runtime.</p>
</section>

<?php if ($vulnerable && $footholdAvailable): ?>
<section class="panel danger">
  <h3>Demonstrated impact</h3>
  <p>This runtime is exposed. The lab includes a clearly-labeled
     <a href="/lab-impact/foothold.php">post-exploitation simulation</a> showing the attacker's
     code-execution context (as <code>www-data</code>) after a successful PHP2Shell RCE.</p>
</section>
<?php elseif (!$vulnerable): ?>
<section class="panel ok">
  <h3>Remediated</h3>
  <p>This runtime is patched. The post-exploitation simulation is <strong>absent</strong> on this
     container — requesting <code>/lab-impact/foothold.php</code> returns 404.</p>
</section>
<?php endif; ?>
<?php
render_footer();
