<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// CSP matches what index.html actually loads: w3.css, Font Awesome, Google Material Icons.
// Inline *scripts* are not allowed (index.html now uses data-action instead of onclick).
// 'unsafe-inline' stays for styles only because index.html has an inline <style> block.
header(
    "Content-Security-Policy: default-src 'self'; " .
    "script-src 'self'; " .
    "style-src 'self' 'unsafe-inline' https://www.w3schools.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; " .
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " .
    "img-src 'self' data:; " .
    "connect-src 'self'; " .
    "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
);
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// HSTS is only meaningful (and only honoured) over HTTPS.
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}
