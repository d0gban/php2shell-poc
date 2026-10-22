<?php
/**
 * PHP2Shell verdict engine — CVE-2026-109618 / CVE-2026-109619
 * Single source of truth consumed by index.php, assess.php and the host scanner.
 *
 * Disclosed 2026-10-21. Both CVSS 9.2, unauthenticated, pre-application-code.
 * Fixed releases per supported branch below. 8.1 and older are EOL/unsupported.
 */

/** Minimum fixed patch version for each still-supported branch. */
const PHP2SHELL_FIXED = [
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
];

const PHP2SHELL_CVES = ['CVE-2026-109618', 'CVE-2026-109619'];

/**
 * Classify a PHP version string against PHP2Shell.
 *
 * @return array{status:string,branch:string,running:string,fixed_in:?string,reason:string,cves:array}
 *   status is one of: VULNERABLE, PATCHED, EOL_UNSUPPORTED
 */
function php2shell_verdict(string $version): array {
    // Normalise e.g. "8.3.10-1+ubuntu" -> major.minor.patch
    preg_match('/^(\d+)\.(\d+)\.(\d+)/', $version, $m);
    $major  = isset($m[1]) ? (int) $m[1] : 0;
    $minor  = isset($m[2]) ? (int) $m[2] : 0;
    $branch = "{$major}.{$minor}";

    $base = [
        'running'  => $version,
        'branch'   => $branch,
        'fixed_in' => PHP2SHELL_FIXED[$branch] ?? null,
        'cves'     => PHP2SHELL_CVES,
    ];

    // Branch 8.1 and earlier: end-of-life, no upstream fix -> treat as exposed.
    if ($major < 8 || ($major === 8 && $minor <= 1)) {
        return $base + [
            'status' => 'EOL_UNSUPPORTED',
            'reason' => "PHP {$branch} is end-of-life and receives no upstream PHP2Shell fix. "
                      . "Exposed to CVE-2026-109618 / CVE-2026-109619. Migrate to a supported, patched branch.",
        ];
    }

    $fixed = PHP2SHELL_FIXED[$branch] ?? null;
    if ($fixed === null) {
        // Unknown future/unknown branch — report conservatively.
        return $base + [
            'status' => 'VULNERABLE',
            'reason' => "Branch {$branch} not in the known fixed-version matrix; verify against the official advisory.",
        ];
    }

    if (version_compare($version, $fixed, '<')) {
        return $base + [
            'status' => 'VULNERABLE',
            'reason' => "PHP {$version} is older than the fixed release {$fixed} for branch {$branch}. "
                      . "Exposed to CVE-2026-109618 / CVE-2026-109619.",
        ];
    }

    return $base + [
        'status' => 'PATCHED',
        'reason' => "PHP {$version} includes the PHP2Shell fix ({$fixed} or later for branch {$branch}).",
    ];
}

/**
 * Audit runtime config against PHP's documented interim mitigations.
 *
 * @return array<int,array{key:string,value:string,recommended:string,ok:bool,note:string}>
 */
function php2shell_mitigations(): array {
    $upload = ini_get('session.upload_progress.enabled');
    $uploadOn = !($upload === '' || $upload === '0' || $upload === false);

    return [
        [
            'key'         => 'session.upload_progress.enabled',
            'value'       => $uploadOn ? '1 (enabled)' : '0 (disabled)',
            'recommended' => '0 (disabled)',
            'ok'          => !$uploadOn,
            'note'        => 'PHP lists disabling session.upload_progress as an interim mitigation (not a full fix).',
        ],
        [
            'key'         => 'memory_limit',
            'value'       => (string) ini_get('memory_limit'),
            'recommended' => 'reviewed / conservative',
            'ok'          => true,
            'note'        => 'Review per PHP guidance; relevant to the request-cleanup corruption (CVE-2026-109618).',
        ],
        [
            'key'         => 'post_max_size',
            'value'       => (string) ini_get('post_max_size'),
            'recommended' => 'reviewed / conservative',
            'ok'          => true,
            'note'        => 'Review per PHP guidance.',
        ],
    ];
}

/** Server-facing exposure context (mod_php is the highest-risk SAPI). */
function php2shell_sapi_context(): array {
    $sapi = PHP_SAPI;
    $highRisk = in_array($sapi, ['apache2handler', 'cgi-fcgi', 'fpm-fcgi'], true);
    return [
        'sapi'      => $sapi,
        'high_risk' => $highRisk,
        'note'      => $sapi === 'apache2handler'
            ? 'apache2handler (mod_php) — the SAPI PHP rates as highest risk for PHP2Shell.'
            : 'SAPI: ' . $sapi,
    ];
}
