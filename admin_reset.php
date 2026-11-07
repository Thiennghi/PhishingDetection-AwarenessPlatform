<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
function resetReply(int $status, array $data): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function isLocalResetRequest(): bool {
    $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    return in_array($remote, ['127.0.0.1', '::1', '::ffff:127.0.0.1'], true);
}
function saveAdminCredentials(string $root, string $username, string $password): void {
    $file = $root . '/admin_secrets.php';
    $contents = "<?php\n// Generated admin credentials. Keep private; do not commit or share.\nreturn " . var_export([
        'username' => $username,
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'secret_token' => bin2hex(random_bytes(32)),
    ], true) . ";\n";
    $temp = $root . '/.admin_secrets.' . bin2hex(random_bytes(8)) . '.tmp';
    $handle = @fopen($temp, 'x');
    if (!$handle) resetReply(500, ['success' => false, 'message' => 'Could not create temporary configuration. Check folder permissions.']);
    try {
        if (fwrite($handle, $contents) !== strlen($contents)) throw new RuntimeException('Incomplete write');
        fflush($handle);
    } catch (Throwable $e) {
        fclose($handle); @unlink($temp);
        error_log('admin_reset.php: ' . $e->getMessage());
        resetReply(500, ['success' => false, 'message' => 'Could not save administrator settings. Existing credentials were not intentionally changed.']);
    }
    fclose($handle); @chmod($temp, 0600);
    $old = null;
    if (is_file($file)) {
        $old = $root . '/.admin_secrets.' . bin2hex(random_bytes(8)) . '.old';
        if (!@rename($file, $old)) { @unlink($temp); resetReply(500, ['success' => false, 'message' => 'Could not safely replace credentials. Check folder permissions.']); }
    }
    if (!@rename($temp, $file)) {
        if ($old !== null) @rename($old, $file);
        @unlink($temp);
        resetReply(500, ['success' => false, 'message' => 'Could not install new credentials. Existing credentials were restored where possible.']);
    }
    @chmod($file, 0600);
    if ($old !== null) @unlink($old);
}
$root = __DIR__;
$recoveryKeyFile = $root . '/admin_recovery_key.php';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    if (isLocalResetRequest()) resetReply(200, ['success' => true, 'local_only' => true, 'message' => 'Local recovery is available on this computer.']);
    if (is_file($recoveryKeyFile)) resetReply(200, ['success' => true, 'local_only' => false, 'message' => 'Hosted recovery is enabled for one reset. Enter the one-time recovery key and choose new credentials.']);
    resetReply(200, ['success' => true, 'local_only' => false, 'message' => 'For InfinityFree: create admin_recovery_key.php privately in this project folder using the instructions in ADMIN-SETUP.md, then return here.']);
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') resetReply(405, ['success' => false, 'message' => 'Method not allowed.']);
$contentType = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
if (strpos($contentType, 'application/json') !== false) {
    $payload = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($payload)) resetReply(400, ['success' => false, 'message' => 'Invalid request.']);
} else $payload = $_POST;
$username = $payload['username'] ?? '';
$password = $payload['password'] ?? '';
$confirm = $payload['confirm_password'] ?? '';
$recoveryKey = $payload['recovery_key'] ?? '';
if (!isLocalResetRequest()) {
    if (!is_file($recoveryKeyFile) || !is_string($recoveryKey) || $recoveryKey === '') {
        resetReply(403, ['success' => false, 'message' => 'Hosted recovery is locked. Create the one-time admin_recovery_key.php file using ADMIN-SETUP.md, then enter its key.']);
    }
    $storedKey = require $recoveryKeyFile;
    if (!is_string($storedKey) || strlen($storedKey) < 32 || !hash_equals($storedKey, $recoveryKey)) {
        resetReply(403, ['success' => false, 'message' => 'Recovery key is incorrect. Check the private key file and try again.']);
    }
}

if (!is_string($username) || !is_string($password) || !is_string($confirm)) resetReply(400, ['success' => false, 'message' => 'Please enter valid values.']);
$username = trim($username);
if ($username === '' || strlen($username) > 100 || preg_match('/[\x00-\x1F\x7F]/', $username)) resetReply(400, ['success' => false, 'message' => 'Username must be 1–100 characters and contain no control characters.']);
if (strlen($password) < 12 || strlen($password) > 1024) resetReply(400, ['success' => false, 'message' => 'Use a unique password between 12 and 1024 bytes.']);
if (!hash_equals($password, $confirm)) resetReply(400, ['success' => false, 'message' => 'The passwords do not match.']);
saveAdminCredentials($root, $username, $password);
if (!isLocalResetRequest() && is_file($recoveryKeyFile) && !@unlink($recoveryKeyFile)) { error_log('admin_reset.php: recovery succeeded but one-time key file could not be removed'); }
resetReply(200, ['success' => true, 'username' => $username, 'message' => 'Administrator credentials reset. Sign in using your new username and password. Existing report data was not changed.']);
