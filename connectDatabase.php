<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

/**
 * Opens the database connection. mysqli is switched to exception mode so failed queries
 * actually throw (on PHP < 8.1 they silently returned false, which broke the old try/catch blocks).
 *
 * Order: live server -> local XAMPP -> error.
 */

/** Which target connected: 'live' or 'local' (null until connectDatabase() succeeds). */
function activeDbSource(?string $set = null): ?string {
    static $source = null;
    if ($set !== null) {
        $source = $set;
    }
    return $source;
}

/** Ordered connection targets built from the config. */
function dbTargets(): array {
    global $config;

    $db      = $config['db'];
    $targets = [];

    if (trim((string) $db['live']['host']) !== '') {
        $targets['live'] = $db['live'];
    }
    if (!empty($db['local_fallback'])) {
        $targets['local'] = $db['local'];
    }

    return $targets;
}

function connectDatabase(): mysqli {
    global $config;

    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $timeout   = max(1, (int) ($config['db']['connect_timeout'] ?? 2));
    $liveSet   = trim((string) $config['db']['live']['host']) !== '';
    $lastError = null;

    foreach (dbTargets() as $label => $t) {
        try {
            $mysqli = mysqli_init();
            $mysqli->options(MYSQLI_OPT_CONNECT_TIMEOUT, $timeout);
            $mysqli->real_connect((string) $t['host'], (string) $t['user'], (string) $t['pass'], (string) $t['name'], (int) $t['port']);
            $mysqli->set_charset('utf8mb4');

            activeDbSource($label);
            if ($label === 'local' && $liveSet) {
                error_log('[db] Live database unreachable; using local XAMPP database.');
            }
            return $mysqli;
        } catch (Throwable $e) {
            $lastError = $e;
            error_log("[db] '{$label}' connection failed: " . $e->getMessage());
        }
    }

    $message = 'Database connection failed: the live server and local XAMPP MySQL are both unreachable.';

    // Web requests get a clean JSON error; CLI scripts/tests get an exception.
    if (PHP_SAPI !== 'cli' && function_exists('jsonResponse')) {
        jsonResponse(503, ['success' => false, 'message' => $message]);
    }
    throw new RuntimeException($message, 0, $lastError);
}
