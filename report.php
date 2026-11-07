<?php
declare(strict_types=1);

/** POST report.php - stores a user-submitted threat report. */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/communityReports.php';

// Allow-list: keys must match the <option value=""> entries of #threatType in index.html.
const REPORT_CATEGORIES = [
    'phishing' => 'Phishing Email / SMS',
    'scam'     => 'Financial Scam',
    'malware'  => 'Malicious URL / Link',
];

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    jsonResponse(405, ['success' => false, 'message' => 'Method not allowed.'], ['Allow: POST']);
}

$conn = connectDatabase();

try {
    validateCsrf();
    enforceRateLimit($conn, 'report');

    $categoryKey = $_POST['category'] ?? '';
    $raw         = $_POST['description'] ?? '';

    if (!is_string($categoryKey) || !is_string($raw) || !array_key_exists($categoryKey, REPORT_CATEGORIES)) {
        jsonResponse(400, ['success' => false, 'message' => 'Invalid report category.']);
    }

    $rawUrl = $_POST['url'] ?? '';
    if (!is_string($rawUrl)) jsonResponse(400,['success'=>false,'message'=>'Invalid URL.']);
    try { $link = communityUrl($rawUrl); } catch (InvalidArgumentException $e) { jsonResponse(400,['success'=>false,'message'=>$e->getMessage()]); }
    if (trim($raw)==='' && $link) $raw='Suspicious URL submitted for review.';
    if (!mb_check_encoding($raw,'UTF-8')) jsonResponse(400,['success'=>false,'message'=>'Invalid text encoding.']);
    $maxLength = (int) $config['security']['max_report_length'];
    if (mb_strlen($raw, 'UTF-8') > $maxLength) {
        jsonResponse(400, ['success' => false, 'message' => "Report is too long. Maximum length is {$maxLength} characters."]);
    }

    if (isLikelyBadInput($raw)) {
        jsonResponse(400, ['success' => false, 'message' => 'Report contains potentially malicious code and was rejected.']);
    }

    $description = normalizeInput(sanitizeText($raw));
    if (mb_strlen($description, 'UTF-8') < 5) {
        jsonResponse(400, ['success' => false, 'message' => 'Please enter at least 5 characters.']);
    }

    $category = REPORT_CATEGORIES[$categoryKey];

    $conn->begin_transaction();
    $stmt = $conn->prepare("INSERT INTO reports (scan_id, source, category, description) VALUES (NULL, 'user', ?, ?)");
    $stmt->bind_param('ss', $category, $description);
    $stmt->execute();
    $reportId = $stmt->insert_id;
    $stmt->close();
    $submittedUrl = $link['url'] ?? null; $hash = $link['hash'] ?? null;
    $queue = $conn->prepare('INSERT INTO community_reports (report_id,submitted_url,url_hash) VALUES (?,?,?)');
    $queue->bind_param('iss',$reportId,$submittedUrl,$hash);$queue->execute();$queue->close();
    $conn->commit();$conn->close();

    jsonResponse(200, ['success' => true, 'report_id'=>$reportId,'status'=>'pending','message' => 'Report #'.$reportId.' saved. Awaiting administrator review.']);
} catch (Throwable $e) {
    try { $conn->rollback(); } catch (Throwable $ignored) {}
    error_log('report.php failed: ' . $e->getMessage());
    jsonResponse(500, ['success' => false, 'message' => 'Failed to save the report.']);
}
