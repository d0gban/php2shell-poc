<?php
/**
 * [LAB SIMULATION] Post-exploitation impact demonstrator.
 *
 * This is NOT a working exploit for CVE-2026-109618 / CVE-2026-109619 — the real
 * memory-corruption primitive is not public. This page stands in for the foothold an
 * attacker holds AFTER a successful PHP2Shell RCE, to demonstrate impact for a report.
 *
 * Safety: it runs a FIXED, read-only allowlist of commands. There is no user-controlled
 * command parameter, so it is a demonstration — not a reusable webshell. This file is
 * baked only into the EOL/outdated images and is absent on the patched image.
 */
require __DIR__ . '/../includes/cve.php';
require __DIR__ . '/../includes/layout.php';

// Fixed, read-only diagnostic commands. No input is taken from the request.
$allowlist = [
    'whoami'    => 'id',
    'host'      => 'hostname',
    'kernel'    => 'uname -a',
    'php'       => 'php -v',
    'webroot'   => 'ls -la /var/www/html',
];

$results = [];
foreach ($allowlist as $label => $cmd) {
    // escapeshellcmd is defensive only; commands are hardcoded literals above.
    $out = @shell_exec(escapeshellcmd($cmd) . ' 2>&1');
    $results[$label] = ['cmd' => $cmd, 'out' => trim((string) $out)];
}

$verdict = php2shell_verdict(PHP_VERSION);

render_header('Post-Exploitation Simulation');
?>
<div class="sim-banner">
  [LAB SIMULATION] — This is NOT a working CVE-2026-109618 / CVE-2026-109619 exploit.
  It demonstrates attacker impact <em>after</em> RCE, using a fixed read-only command allowlist.
</div>

<section class="panel danger">
  <h2>Simulated foothold on <code><?= htmlspecialchars(PHP_VERSION) ?></code></h2>
  <p>Scenario: an unauthenticated PHP2Shell request achieved remote code execution in the
     PHP worker (highest risk under Apache <code>mod_php</code>). Code now runs with the web
     server's privileges. The output below is produced by the server itself to illustrate the
     access an attacker would hold — it is the <strong>consequence</strong>, not the exploit.</p>

  <div class="term"><?php foreach ($results as $label => $r): ?>
<span class="cmd">www-data@<?= htmlspecialchars(gethostname()) ?>:/var/www/html$ <?= htmlspecialchars($r['cmd']) ?></span>
<?= htmlspecialchars($r['out']) ?>

<?php endforeach; ?><span class="meta"># ^ read-only allowlist output. A real attacker would have arbitrary code execution here:
# read secrets/config, pivot, install a persistent webshell, or move laterally.</span></div>
</section>

<section class="panel">
  <h3>Why this matters</h3>
  <p><?= htmlspecialchars($verdict['reason']) ?></p>
  <p>On the <strong>patched</strong> container this page does not exist (HTTP 404) and the runtime
     is not exposed. See <a href="/assess.php">the self-assessment</a> for the full verdict and the
     <a href="/">landing page</a> for the version comparison.</p>
</section>
<?php
render_footer();
