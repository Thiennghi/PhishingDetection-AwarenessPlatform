<?php
declare(strict_types=1);
/**
 * One-time local administrator setup. Intentionally independent of bootstrap.php so
 * this page remains usable before production admin secrets have been configured.
 * For remote hosting, use scripts/setup_admin.php over SSH/CLI instead.
 */
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function setupReply(int $status, array $data): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function adminAlreadyConfigured(string $root): bool {
    if (is_file($root . '/admin_secrets.php')) return true;
    if ((getenv('ADMIN_PASSWORD_HASH') ?: '') !== '' || (getenv('ADMIN_SECRET_TOKEN') ?: '') !== '') return true;
    $localFile = $root . '/config_local_live.php';
    if (is_file($localFile)) {
        $local = require $localFile;
        if (is_array($local) && isset($local['admin']) && is_array($local['admin'])) {
            if (!empty($local['admin']['password_hash']) || !empty($local['admin']['secret_token'])) return true;
        }
    }
    return false;
}
function isLocalRequest(): bool {
    $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    return in_array($remote, ['127.0.0.1', '::1', '::ffff:127.0.0.1'], true);
}
/** Hosted (InfinityFree) setup: a private one-time key file created in the file manager unlocks the browser setup. */
function setupKeyFile(string $root): ?string {
    foreach (['admin_setup_key.php', 'admin_recovery_key.php'] as $name) {
        if (is_file($root . '/' . $name)) return $root . '/' . $name;
    }
    return null;
}
$root = __DIR__;
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'GET') {
    $local = isLocalRequest();
    setupReply(200, ['success' => true, 'configured' => adminAlreadyConfigured($root), 'local' => $local, 'local_only' => $local,
        'needs_key' => !$local, 'key_file_present' => setupKeyFile($root) !== null]);
}
if ($method !== 'POST') setupReply(405, ['success' => false, 'message' => 'Method not allowed.']);
if (adminAlreadyConfigured($root)) setupReply(409, ['success' => false, 'message' => 'Administrator setup has already been completed.']);

$contentType = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
if (strpos($contentType, 'application/json') !== false) {
    $payload = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($payload)) setupReply(400, ['success' => false, 'message' => 'Invalid request.']);
} else {
    $payload = $_POST;
}
$keyFile = null;
if (!isLocalRequest()) {
    $keyFile = setupKeyFile($root);
    if ($keyFile === null) setupReply(403, ['success' => false, 'message' => 'Hosted setup is locked. In your hosting file manager create admin_setup_key.php with a private random key (see ADMIN-SETUP.md), then enter that key here.']);
    $given = $payload['setup_key'] ?? '';
    $stored = is_string($given) ? require $keyFile : null;
    if (!is_string($given) || !is_string($stored) || strlen($stored) < 32 || !hash_equals($stored, $given)) {
        usleep(700000); // slow down key guessing
        setupReply(403, ['success' => false, 'message' => 'Setup key is incorrect. Copy it exactly from the key file on the server.']);
    }
}
$username = $payload['username'] ?? 'admin';
$password = $payload['password'] ?? '';
$confirm = $payload['confirm_password'] ?? '';
if (!is_string($username) || !is_string($password) || !is_string($confirm)) setupReply(400, ['success' => false, 'message' => 'Please enter valid values.']);
$username = trim($username);
if ($username === '' || strlen($username) > 100 || preg_match('/[\x00-\x1F\x7F]/', $username)) setupReply(400, ['success' => false, 'message' => 'Username must be 1–100 characters and contain no control characters.']);
if (strlen($password) < 12) setupReply(400, ['success' => false, 'message' => 'Use a unique password with at least 12 characters.']);
if (strlen($password) > 1024) setupReply(400, ['success' => false, 'message' => 'Password is too long.']);
if (!hash_equals($password, $confirm)) setupReply(400, ['success' => false, 'message' => 'The passwords do not match.']);

$file = $root . '/admin_secrets.php';
$contents = "<?php\n// Generated admin credentials. Keep private; do not commit or share.\nreturn " . var_export([
    'username' => $username,
    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
    'secret_token' => bin2hex(random_bytes(32)),
], true) . ";\n";
$handle = @fopen($file, 'x'); // exclusive creation prevents concurrent first-setup races
if (!$handle) setupReply(409, ['success' => false, 'message' => 'Administrator setup has already started or the server cannot write its configuration.']);
try {
    if (fwrite($handle, $contents) !== strlen($contents)) throw new RuntimeException('Could not write complete administrator configuration.');
    fflush($handle);
} catch (Throwable $e) {
    fclose($handle); @unlink($file); error_log('admin_setup.php: '.$e->getMessage());
    setupReply(500, ['success' => false, 'message' => 'Could not save administrator settings. Check folder permissions.']);
}
fclose($handle);
@chmod($file, 0600);
if ($keyFile !== null && !@unlink($keyFile)) error_log('admin_setup.php: setup succeeded but the one-time key file could not be removed; delete it manually.');
setupReply(201, ['success' => true, 'message' => 'Administrator account created. Sign in with the username and password you just chose.']);
