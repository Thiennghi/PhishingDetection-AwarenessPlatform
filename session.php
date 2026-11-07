<?php
declare(strict_types=1);

function isHttps(): bool {
    global $config;

    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    if (!empty($config['security']['trust_proxy'])
        && ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
        return true;
    }

    return false;
}

/**
 * Single place that starts the session. The cookie is only marked "secure" on HTTPS,
 * otherwise it would never be stored on http://localhost and CSRF/admin sessions break.
 */
function startSecureSession(): void {
    if (session_status() !== PHP_SESSION_NONE) {
        return;
    }

    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => isHttps(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}
