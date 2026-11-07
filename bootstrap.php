<?php
declare(strict_types=1);

/**
 * Every endpoint requires this file first. It loads config, sends the security headers,
 * and provides jsonResponse().
 */

/* Compatibility for hosts still running PHP 7.x (these functions are built in from PHP 8.0). */
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool {
        return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
    }
}
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}

require_once __DIR__ . '/security_headers.php';
set_exception_handler(function (Throwable $error): void {
    error_log((string) $error);
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['success'=>false,'message'=>'Request could not be completed.']);
});
require_once __DIR__ . '/config.php';

/** Sends a JSON response and stops the script. */
function jsonResponse(int $status, array $data, array $extraHeaders = []): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    foreach ($extraHeaders as $header) {
        header($header);
    }

    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

require_once __DIR__ . '/session.php';
require_once __DIR__ . '/inputSecurity.php';
require_once __DIR__ . '/connectDatabase.php';
