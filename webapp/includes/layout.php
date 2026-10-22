<?php
/** Shared chrome so the lab app looks like a small real website. */
function render_header(string $title): void {
    $running = PHP_VERSION;
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($title) ?> — Acme Intranet Portal</title>
<link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<header class="topbar">
  <div class="brand"><span class="logo">▣</span> Acme Intranet Portal</div>
  <nav>
    <a href="/">Home</a>
    <a href="/assess.php">Security Self-Check</a>
  </nav>
  <div class="verrun">PHP <?= htmlspecialchars($running) ?></div>
</header>
<main class="wrap">
<?php
}

function render_footer(): void {
    ?>
</main>
<footer class="foot">
  <p><strong>LAB ENVIRONMENT — vulnerable by design.</strong>
  For authorized security research &amp; patch-management demonstration only.
  Do not deploy on any internet-facing or production host.</p>
</footer>
</body>
</html>
<?php
}

/** Map a verdict status to a CSS badge class + label. */
function badge(string $status): string {
    $map = [
        'VULNERABLE'       => ['bad',  'VULNERABLE'],
        'EOL_UNSUPPORTED'  => ['bad',  'VULNERABLE · EOL'],
        'PATCHED'          => ['good', 'PATCHED'],
    ];
    [$cls, $label] = $map[$status] ?? ['warn', $status];
    return '<span class="badge ' . $cls . '">' . htmlspecialchars($label) . '</span>';
}
