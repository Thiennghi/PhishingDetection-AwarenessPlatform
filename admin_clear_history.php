<?php
declare(strict_types=1);

/**
 * POST admin_clear_history.php - deletes ALL scans and reports. ADMIN ONLY.
 * (Formerly awareness_table.php, which was open to anyone on the internet.)
 *
 *   curl -X POST https://your-site/admin_clear_history.php -H "X-Admin-Secret: <ADMIN_SECRET_TOKEN>"
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/auth.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    jsonResponse(405, ['success' => false, 'message' => 'Method not allowed.'], ['Allow: POST']);
}

$conn = connectDatabase();

// Throttle guessing of the admin secret before checking it.
enforceRateLimit($conn, 'admin', 10, 300);

$authMethod = requireAdmin();
if ($authMethod === 'session') {
    validateCsrf();   // header-secret requests can't be forged cross-site, session ones can
}

try {
    $conn->begin_transaction();
    $conn->query('DELETE FROM reports');
    $conn->query('DELETE FROM scans');
    $conn->commit();

    // DDL causes an implicit commit in MySQL, so it runs after the transaction.
    $conn->query('ALTER TABLE reports AUTO_INCREMENT = 1');
    $conn->query('ALTER TABLE scans AUTO_INCREMENT = 1');
    $conn->close();

    jsonResponse(200, ['success' => true, 'message' => 'Database cleared successfully.']);
} catch (Throwable $e) {
    try { $conn->rollback(); } catch (Throwable $ignored) {}
    error_log('admin_clear_history failed: ' . $e->getMessage());
    jsonResponse(500, ['success' => false, 'message' => 'Failed to clear the database.']);
}
