<?php
declare(strict_types=1);

/**
 * Central configuration.
 *
 * Values come from environment variables. For local development (XAMPP etc.) you can
 * instead create a git-ignored config_local_live.php that returns an array of overrides.
 *
 * DATABASE: connectDatabase.php tries "live" (DB_HOST etc. or config_local_live.php) first, then the
 * local XAMPP database, then returns a "Database connection failed" error.
 *
 * APP_ENV=development relaxes the "must have admin secrets" checks so the app runs on a
 * default XAMPP install. In production (the default) they are mandatory.
 */

function failStartup(string $message): void {
    error_log($message);
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['success' => false, 'message' => 'Server is not configured correctly.']);
    exit(1);
}

$appEnv = getenv('APP_ENV') ?: 'production';

$config = [
    'env' => $appEnv,
    'db' => [
        // 1) Live server (tried first). Skipped when host is empty.
        'live' => [
            'host' => getenv('DB_HOST') ?: '',
            'port' => (int)(getenv('DB_PORT') ?: '3306'),
            'name' => getenv('DB_NAME') ?: 'cyberguard_db',
            'user' => getenv('DB_USER') ?: '',
            'pass' => getenv('DB_PASS') ?: '',
        ],
        // 2) Local XAMPP (fallback).
        'local' => [
            'host' => '127.0.0.1',
            'port' => 3306,
            'name' => 'cyberguard_db',
            'user' => 'root',
            'pass' => '',
        ],
        'local_fallback'  => getenv('DB_LOCAL_FALLBACK') !== '0',   // DB_LOCAL_FALLBACK=0 turns step 2 off
        'connect_timeout' => 2,                                     // seconds per attempt
    ],
    'admin' => [
        'username'      => getenv('ADMIN_USERNAME') ?: 'admin',
        'password_hash' => getenv('ADMIN_PASSWORD_HASH') ?: '',
        'secret_token'  => getenv('ADMIN_SECRET_TOKEN') ?: '',
    ],
    'security' => [
        'max_input_length'  => 5000,   // analysis text
        'max_report_length' => 3000,   // user threat reports
        'rate_limit_max'    => 10,     // requests per window, per IP
        'rate_limit_window' => 60,     // seconds
        // Only trust CF-Connecting-IP / X-Forwarded-For when you really are behind a proxy.
        'trust_proxy'       => getenv('TRUST_PROXY') === '1',
    ],
];

// ONE local config file: config_local_live.php (holds the live AND the XAMPP database settings).
$localFile = __DIR__ . '/config_local_live.php';
if (is_file($localFile)) {
    $local = require $localFile;
    if (is_array($local)) {
        $config = array_replace_recursive($config, $local);
    }
}

// Administrator credentials are isolated from database configuration.
// This optional file is created by scripts/setup_admin.php and must never be committed.
$adminSecretsFile = __DIR__ . '/admin_secrets.php';
if (is_file($adminSecretsFile)) {
    $adminSecrets = require $adminSecretsFile;
    if (is_array($adminSecrets)) {
        $allowedAdminKeys = ['username', 'password_hash', 'secret_token'];
        $config['admin'] = array_replace($config['admin'], array_intersect_key($adminSecrets, array_flip($allowedAdminKeys)));
    }
}

if ($config['env'] !== 'development') {
    if ($config['admin']['password_hash'] === '') {
        failStartup('ADMIN_PASSWORD_HASH is required in production. Use password_hash() output.');
    }
    if ($config['admin']['secret_token'] === '') {
        failStartup('ADMIN_SECRET_TOKEN is required in production. Use a strong random token.');
    }
}
