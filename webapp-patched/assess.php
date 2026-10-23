<?php
require __DIR__ . '/includes/cve.php';

$verdict     = php2shell_verdict(PHP_VERSION);
$mitigations = php2shell_mitigations();
$config      = php2shell_config_audit();
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
        'config_audit' => $config,
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
  <h3>Runtime configuration vs. hardened baseline</h3>
  <p>This host's live PHP configuration, directive by directive. <strong>Factory default</strong> is the
     stock <code>php.ini-production</code> baseline the image ships with; <strong>Current config</strong>
     is what is live now (this lab applies <code>config/php2shell-tune.ini</code> on top, so some rows are
     deliberately weakened); <strong>Patched config</strong> is the hardened target. On a host that
     <em>cannot upgrade</em>, driving each row to its patched value is a config-layer virtual patch — but a
     patched runtime is safe even with these set, because the PHP2Shell fix is in code.</p>
  <table class="grid">
    <thead><tr><th>Setting</th><th>Factory default</th><th>Current config</th><th>Patched config</th><th>State</th></tr></thead>
    <tbody>
    <?php foreach ($config as $c): ?>
      <tr>
        <td><code><?= htmlspecialchars($c['key']) ?></code><br><span class="muted"><?= htmlspecialchars($c['note']) ?></span></td>
        <td><?= htmlspecialchars($c['factory']) ?></td>
        <td><?= htmlspecialchars($c['current']) ?></td>
        <td><?= htmlspecialchars($c['patched']) ?></td>
        <td><?php
          if ($c['ok'] === null)      echo '<span class="badge warn">INFO</span>';
          elseif ($c['ok'] === true)  echo '<span class="badge good">OK</span>';
          else                        echo '<span class="badge bad">EXPOSED</span>';
        ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <p class="muted">Two further preconditions can't be read from runtime config — audit them in your
     application code: (1) an <code>include()</code>/<code>require()</code> sink reachable with
     attacker-influenced input — present in this lab at <a href="/view.php?doc=welcome.php">/view.php</a>
     (LFI); and (2) mixing <code>session.serialize_handler</code> values across session save paths.
     Session fixation (<a href="/login.php">/login.php</a>) rides on
     <code>session.use_strict_mode = 0</code> above. Remove all three where present.</p>
  <p class="muted">Config hardening reduces exposure but is <strong>not</strong> a substitute for patching the PHP runtime.</p>
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
