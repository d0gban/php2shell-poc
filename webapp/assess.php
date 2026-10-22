<?php
require __DIR__ . '/includes/cve.php';

$verdict     = php2shell_verdict(PHP_VERSION);
$mitigations = php2shell_mitigations();
$sapi        = php2shell_sapi_context();
$vulnerable  = in_array($verdict['status'], ['VULNERABLE', 'EOL_UNSUPPORTED'], true);

// Machine-readable output for the host scanner.
if (($_GET['format'] ?? '') === 'json') {
    header('Content-Type: application/json');
    echo json_encode([
        'php_version'  => PHP_VERSION,
        'status'       => $verdict['status'],
        'vulnerable'   => $vulnerable,
        'branch'       => $verdict['branch'],
        'fixed_in'     => $verdict['fixed_in'],
        'cves'         => $verdict['cves'],
        'reason'       => $verdict['reason'],
        'sapi'         => $sapi,
        'mitigations'  => $mitigations,
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
  <h3>Exposure preconditions</h3>
  <p>The attack chains through PHP's <code>session.upload_progress</code> handling. The table audits
     this runtime's live configuration against the exposure preconditions — these are the real
     defaults it ships with, not lab tuning. On a host that <em>cannot upgrade</em>, breaking these
     preconditions is a config-layer virtual patch. A patched runtime is safe even with them set,
     because the fix is in code.</p>
  <table class="grid">
    <thead><tr><th>Setting</th><th>Current</th><th>Interim-mitigation value</th><th>State</th></tr></thead>
    <tbody>
    <?php foreach ($mitigations as $m): ?>
      <tr>
        <td><code><?= htmlspecialchars($m['key']) ?></code><br><span class="muted"><?= htmlspecialchars($m['note']) ?></span></td>
        <td><?= htmlspecialchars($m['value']) ?></td>
        <td><?= htmlspecialchars($m['recommended']) ?></td>
        <td><?= $m['ok'] ? '<span class="badge good">OK</span>' : '<span class="badge bad">EXPOSED</span>' ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <p class="muted">Two further preconditions can't be read from runtime config — audit them in your
     application code: (1) an <code>include()</code>/<code>require()</code> sink reachable with
     attacker-influenced input (LFI), and (2) mixing <code>session.serialize_handler</code> values
     across session save paths. Remove both where present.</p>
  <p class="muted">Interim mitigations reduce exposure but are <strong>not</strong> a substitute for patching the PHP runtime.</p>
</section>

<?php if ($vulnerable): ?>
<section class="panel danger">
  <h3>Blue-team reference target</h3>
  <p>This is a genuinely affected, production-shaped PHP runtime on
     <code>http://localhost:<?= htmlspecialchars((string)($_SERVER['SERVER_PORT'] ?? '')) ?></code>.
     Use it to capture the real server fingerprint (banners, <code>Server</code> / <code>X-Powered-By</code>
     headers, error behaviour) and to develop and test firewall / WAF and detection rules against an
     authentic vulnerable build. Compare against the patched host (:8082) to keep false positives down.</p>
</section>
<?php else: ?>
<section class="panel ok">
  <h3>Patched baseline</h3>
  <p>This runtime includes the PHP2Shell fix. Use it as the known-good baseline: rules tuned on the
     affected hosts should <em>not</em> fire here, which is how you confirm they target the vulnerability
     and not just &ldquo;any PHP server&rdquo;.</p>
</section>
<?php endif; ?>
<?php
render_footer();
