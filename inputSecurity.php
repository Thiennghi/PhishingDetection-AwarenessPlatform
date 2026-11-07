<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/session.php';

/* ---------- Text cleaning ---------- */

function sanitizeText(string $value): string {
    $value = trim($value);

    // Remove control characters but keep tab / newline / carriage return.
    $clean = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value);

    if ($clean === null) {
        // Invalid UTF-8: replace bad bytes, then retry.
        $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        $clean = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '';
    }

    return strip_tags($clean);
}

function normalizeInput(string $value): string {
    $value = preg_replace('/\s+/u', ' ', $value) ?? $value;
    return trim($value);
}

function isLikelyBadInput(string $value): bool {
    $badPatterns = [
        '/<script/i',
        '/javascript:/i',
        '/vbscript:/i',
        '/onload\s*=/i',
        '/onerror\s*=/i',
        '/<iframe/i',
        '/data:text\/html/i',
        '/%0d%0a/i',
    ];

    foreach ($badPatterns as $pattern) {
        if (preg_match($pattern, $value)) {
            return true;
        }
    }

    return false;
}

/* ---------- Client IP ---------- */

function getClientIp(): string {
    global $config;

    $candidates = [];

    // Forwarded headers can be forged by anyone, so they are ignored unless TRUST_PROXY=1.
    if (!empty($config['security']['trust_proxy'])) {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $candidates[] = $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $candidates[] = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        }
    }

    $candidates[] = $_SERVER['REMOTE_ADDR'] ?? '';

    foreach ($candidates as $ip) {
        $ip = trim((string) $ip);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }

    return '0.0.0.0';
}

/* ---------- Rate limiting (stored in the database, NOT in the session) ---------- */

/**
 * Counts one hit for this IP + bucket and reports whether it is still within the limit.
 * Uses a single atomic INSERT ... ON DUPLICATE KEY UPDATE, so concurrent requests can't race.
 *
 * @return array{0: bool, 1: int} [allowed, secondsUntilWindowResets]
 */
function rateLimitHit(mysqli $conn, string $bucket, int $limit, int $window): array {
    $ip     = getClientIp();
    $now    = time();
    $cutoff = $now - $window;

    $stmt = $conn->prepare(
        'INSERT INTO rate_limits (ip, bucket, window_start, hits) VALUES (?, ?, ?, 1)
         ON DUPLICATE KEY UPDATE
            hits = IF(window_start <= ?, 1, hits + 1),
            window_start = IF(window_start <= ?, ?, window_start)'
    );
    $stmt->bind_param('ssiiii', $ip, $bucket, $now, $cutoff, $cutoff, $now);
    $stmt->execute();
    $stmt->close();

    $stmt = $conn->prepare('SELECT hits, window_start FROM rate_limits WHERE ip = ? AND bucket = ?');
    $stmt->bind_param('ss', $ip, $bucket);
    $stmt->execute();
    $stmt->bind_result($hits, $windowStart);
    $stmt->fetch();
    $stmt->close();

    // Occasionally purge old rows so the table doesn't grow forever.
    if (random_int(1, 100) === 1) {
        $old = $now - 86400;
        $purge = $conn->prepare('DELETE FROM rate_limits WHERE window_start < ?');
        $purge->bind_param('i', $old);
        $purge->execute();
        $purge->close();
    }

    $retryAfter = max(1, (int) $windowStart + $window - $now);

    return [((int) $hits) <= $limit, $retryAfter];
}

function enforceRateLimit(mysqli $conn, string $bucket = 'scan', ?int $limit = null, ?int $window = null): void {
    global $config;

    $limit  = $limit  ?? (int) $config['security']['rate_limit_max'];
    $window = $window ?? (int) $config['security']['rate_limit_window'];

    [$allowed, $retryAfter] = rateLimitHit($conn, $bucket, $limit, $window);

    if (!$allowed) {
        jsonResponse(
            429,
            ['success' => false, 'message' => 'Too many requests. Please wait a moment.'],
            ['Retry-After: ' . $retryAfter]
        );
    }
}

/* ---------- CSRF ---------- */

function csrfToken(): string {
    startSecureSession();

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

/** Accepts the token from the X-CSRF-Token header (preferred) or a csrf_token POST field. */
function validateCsrf(): void {
    startSecureSession();

    $token    = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? '');
    $expected = $_SESSION['csrf_token'] ?? '';

    if (!is_string($token) || !is_string($expected) || $expected === '' || !hash_equals($expected, $token)) {
        jsonResponse(403, ['success' => false, 'message' => 'Invalid or missing security token. Please reload the page.']);
    }
}
