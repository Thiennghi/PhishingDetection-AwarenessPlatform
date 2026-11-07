<?php
declare(strict_types=1);
/**
 * Recover/reset CyberGuard administrator credentials.
 * Run only from a trusted terminal: php scripts/reset_admin.php
 * This replaces the configured username, password hash and API secret token.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("CLI only. Run this script from a trusted terminal.\n");
}
$root = dirname(__DIR__);
$file = $root . '/admin_secrets.php';

function prompt(string $message): string {
    fwrite(STDOUT, $message);
    return rtrim((string) fgets(STDIN), "\r\n");
}
function promptPassword(string $message): string {
    fwrite(STDOUT, $message);
    $hidden = DIRECTORY_SEPARATOR !== '\\' && function_exists('shell_exec') && trim((string) @shell_exec('command -v stty 2>/dev/null')) !== '';
    if ($hidden) @shell_exec('stty -echo');
    try {
        return rtrim((string) fgets(STDIN), "\r\n");
    } finally {
        if ($hidden) { @shell_exec('stty echo'); fwrite(STDOUT, "\n"); }
    }
}

fwrite(STDOUT, "CyberGuard administrator recovery\n");
fwrite(STDOUT, "This replaces the current administrator username/password and rotates the API secret.\n");
fwrite(STDOUT, "Database settings and report data are not changed.\n\n");
$username = trim(prompt('New administrator username [admin]: '));
if ($username === '') $username = 'admin';
if (strlen($username) > 100 || preg_match('/[\x00-\x1F\x7F]/', $username)) {
    fwrite(STDERR, "Username must be 1–100 characters and contain no control characters. Nothing changed.\n");
    exit(1);
}
$password = promptPassword('New unique password (at least 12 characters): ');
$confirm = promptPassword('Confirm new password: ');
if (strlen($password) < 12 || strlen($password) > 1024) {
    fwrite(STDERR, "Password must be between 12 and 1024 bytes. Nothing changed.\n");
    exit(1);
}
if (!hash_equals($password, $confirm)) {
    fwrite(STDERR, "Passwords do not match. Nothing changed.\n");
    exit(1);
}

$contents = "<?php\n// Generated admin credentials. Keep private; do not commit or share.\nreturn " . var_export([
    'username' => $username,
    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
    'secret_token' => bin2hex(random_bytes(32)),
], true) . ";\n";
$temp = $root . '/.admin_secrets.' . bin2hex(random_bytes(8)) . '.tmp';
$handle = @fopen($temp, 'x');
if (!$handle) { fwrite(STDERR, "Could not create temporary config. Check directory permissions.\n"); exit(1); }
try {
    if (fwrite($handle, $contents) !== strlen($contents)) throw new RuntimeException('Incomplete write');
    fflush($handle);
} catch (Throwable $e) {
    fclose($handle); @unlink($temp);
    fwrite(STDERR, "Could not write new credentials. Existing credentials were not intentionally changed.\n");
    exit(1);
}
fclose($handle);
@chmod($temp, 0600);

// Keep replacement atomic where possible; retain a temporary rollback name only during replacement.
$old = null;
if (is_file($file)) {
    $old = $root . '/.admin_secrets.' . bin2hex(random_bytes(8)) . '.old';
    if (!@rename($file, $old)) {
        @unlink($temp);
        fwrite(STDERR, "Could not safely replace existing credentials. Check permissions.\n");
        exit(1);
    }
}
if (!@rename($temp, $file)) {
    if ($old !== null) @rename($old, $file);
    @unlink($temp);
    fwrite(STDERR, "Could not install new credentials. Existing credentials were restored where possible.\n");
    exit(1);
}
@chmod($file, 0600);
if ($old !== null) @unlink($old);

fwrite(STDOUT, "\nAdministrator credentials reset successfully.\n");
fwrite(STDOUT, "Username: {$username}\n");
fwrite(STDOUT, "Sign in at admin.html using the new password.\n");
fwrite(STDOUT, "All existing sessions should be signed out; the previous API secret is no longer valid.\n");
