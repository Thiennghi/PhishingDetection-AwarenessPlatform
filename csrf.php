<?php
declare(strict_types=1);

/** GET csrf.php - returns the CSRF token for the current session. */

require_once __DIR__ . '/bootstrap.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    jsonResponse(405, ['success' => false, 'message' => 'Method not allowed.'], ['Allow: GET']);
}

jsonResponse(200, ['success' => true, 'token' => csrfToken(), 'max_input_length' => $config['security']['max_input_length'], 'max_report_length' => $config['security']['max_report_length']]);
