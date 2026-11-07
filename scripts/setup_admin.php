<?php
declare(strict_types=1);
/** Run from a terminal: php scripts/setup_admin.php (never via a web browser). */
if (PHP_SAPI !== 'cli') { http_response_code(403); exit('CLI only'); }
$root = dirname(__DIR__);
$file = $root . '/admin_secrets.php';
if (is_file($file)) {
    fwrite(STDERR, "Admin credentials already exist. To rotate, securely back up and remove admin_secrets.php first.\n");
    exit(1);
}
fwrite(STDOUT, "Admin username [admin]: ");
$username = trim((string) fgets(STDIN));
if ($username === '') $username = 'admin';
if (strlen($username) > 100) { fwrite(STDERR, "Username too long.\n"); exit(1); }
fwrite(STDOUT, "Choose a unique administrator password (at least 12 characters): ");
$hidden = DIRECTORY_SEPARATOR !== '\\' && function_exists('shell_exec') && trim((string) shell_exec('command -v stty 2>/dev/null')) !== '';
if ($hidden) shell_exec('stty -echo');
try { $password = rtrim((string) fgets(STDIN), "\r\n"); }
finally { if ($hidden) { shell_exec('stty echo'); fwrite(STDOUT, "\n"); } }
if (strlen($password) < 12) { fwrite(STDERR, "Password must be at least 12 characters. Nothing saved.\n"); exit(1); }
$hash = password_hash($password, PASSWORD_DEFAULT);
$token = bin2hex(random_bytes(32));
$contents = "<?php\n// Generated admin credentials. Keep private; do not commit or share.\nreturn " . var_export([
    'username' => $username,
    'password_hash' => $hash,
    'secret_token' => $token,
], true) . ";\n";
$handle = @fopen($file, 'x');
if (!$handle) { fwrite(STDERR, "Could not safely create admin_secrets.php. Check permissions.\n"); exit(1); }
try { if (fwrite($handle, $contents) !== strlen($contents)) throw new RuntimeException('Incomplete write'); }
catch (Throwable $e) { fclose($handle); @unlink($file); throw $e; }
fclose($handle);
@chmod($file, 0600);
fwrite(STDOUT, "Admin credentials configured in admin_secrets.php. Database settings were not changed.\nUpload this private file securely alongside config.php if configuring a remote host.\n");
