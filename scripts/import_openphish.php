<?php
declare(strict_types=1);
// Operator-only importer. Never download or browse a submitted URL.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
ini_set('display_errors', '0');
$conn = null;
$exitCode = 0;
try {
    if ($argc !== 3) throw new RuntimeException('Usage: php scripts/import_openphish.php /absolute/feed.txt 2026-10-07T20:00:00Z');
    $file = $argv[1];
    if (!is_file($file) || !is_readable($file) || filesize($file) > 32 * 1024 * 1024) throw new RuntimeException('Feed must be a readable local text file up to 32 MiB');
    $observed = strtotime($argv[2]);
    if ($observed === false || $observed > time() + 60 || $observed < time() - 12 * 3600) throw new RuntimeException('Supply the actual UTC download time from the past 12 hours');
    require_once __DIR__ . '/../bootstrap.php';
    require_once __DIR__ . '/../detectionEngine.php';
    $hashes = [];
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $url = trim($line);
        if (!filter_var($url, FILTER_VALIDATE_URL) || !preg_match('~^https?://~i', $url)) throw new RuntimeException('Invalid URL in snapshot; no changes applied');
        $parsed = detectionParseUrl($url);
        if (!$parsed) throw new RuntimeException('Unparseable URL in snapshot');
        $hashes[hash('sha256', $parsed['canonical'])] = true;
    }
    if (!$hashes || count($hashes) > 100000) throw new RuntimeException('Feed must contain 1 to 100000 distinct URLs');
    $conn = connectDatabase();
    $conn->begin_transaction();
    // Replace the source snapshot so removals take effect immediately. Never populate from user reports.
    $conn->query("DELETE FROM threat_indicators WHERE source_id = 'openphish'");
    $expires = gmdate('Y-m-d H:i:s', $observed + 24 * 3600);
    $stmt = $conn->prepare("INSERT INTO threat_indicators (url_hash,source_id,imported_at,expires_at) VALUES (?, 'openphish', UTC_TIMESTAMP(), ?)");
    foreach ($hashes as $hash => $_) {
        $stmt->bind_param('ss', $hash, $expires); $stmt->execute();
    }
    $stmt->close();
    $conn->commit();
    fwrite(STDOUT, count($hashes) . " URL hashes imported; expire at $expires UTC.\n");
} catch (Throwable $error) {
    if ($conn) { try { $conn->rollback(); } catch (Throwable $ignored) {} }
    fwrite(STDERR, $error->getMessage() . "\n");
    $exitCode = 1;
} finally { if ($conn) $conn->close(); }
exit($exitCode);
