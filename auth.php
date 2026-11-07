<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/inputSecurity.php';

/**
 * Requires an admin. Accepts either the X-Admin-Secret header (for curl/scripts)
 * or a logged-in admin session.
 *
 * @return string 'secret' or 'session' (so callers know whether CSRF still applies)
 */
function requireAdmin(): string {
    global $config;

    $expected = (string) $config['admin']['secret_token'];
    $secret   = $_SERVER['HTTP_X_ADMIN_SECRET'] ?? '';

    if ($expected !== '' && is_string($secret) && $secret !== '' && hash_equals($expected, $secret)) {
        return 'secret';
    }

    startSecureSession();

    if (!empty($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
        return 'session';
    }

    jsonResponse(401, ['success' => false, 'message' => 'Unauthorized']);
    return ''; // unreachable
}

/**
 * Admin login. Failed attempts are throttled per IP in the database
 * (5 tries per 15 minutes) - the old session counter reset whenever cookies were cleared.
 */
function loginAdmin(mysqli $conn, string $username, string $password): bool {
    global $config;

    [$allowed] = rateLimitHit($conn, 'admin_login', 5, 900);
    if (!$allowed) {
        return false;
    }

    $hash   = (string) $config['admin']['password_hash'];
    $userOk = hash_equals((string) $config['admin']['username'], $username);
    $passOk = $hash !== '' && password_verify($password, $hash);

    if (!$userOk || !$passOk) {
        return false;
    }

    startSecureSession();
    session_regenerate_id(true);
    $_SESSION['admin_logged_in'] = true;
    return true;
}
