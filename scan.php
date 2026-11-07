<?php
declare(strict_types=1);

/** POST scan.php -> scores + saves a scan, returns {success, risk_score, classification, category, ...} */

require_once __DIR__ . '/bootstrap.php';

require_once __DIR__ . '/detectionEngine.php';
require_once __DIR__ . '/communityReports.php';
require_once __DIR__ . '/scanSummary.php';

function saveScan(mysqli $conn, string $userInput, string $mode = 'message'): array {
    $userInput = trim($userInput);
    if ($userInput === '') {
        return ['success' => false, 'message' => 'Input is empty.'];
    }

    $knowledge = detectionKnowledge($conn);
    $result = detectionEvaluate($userInput, $knowledge, [], $mode);
    $hits = detectionReputation($conn, $userInput, $knowledge);
    $result['reputation_checked'] = true;
    $feed = $conn->query("SELECT COUNT(*) AS active_count FROM threat_indicators WHERE expires_at > UTC_TIMESTAMP()")->fetch_assoc();
    $result['active_reputation_entries'] = (int) $feed['active_count'];
    $result = summarizeLinks($result, applyLinkReputation($result['urls'], $hits, $result['active_reputation_entries']));
    $result = summarizeLinks($result, applyCommunityReputation($conn,$result['urls']));
    $result['community_checked'] = true;
    $result['scan_mode'] = $mode;
    $classification = $result['classification'];
    $category = $result['category'];
    $riskScore = $result['risk_score'];
    $version = $result['detector_version'];
    // Evidence stores fixed rule metadata only, never matched text or submitted URLs.
    $evidence = json_encode($result['evidence'], JSON_THROW_ON_ERROR);

    $stmt = $conn->prepare("INSERT INTO scans (input_type, classification, risk_score, input_length, detector_version, evidence_json) VALUES (?, ?, ?, ?, ?, ?)");
    if (!$stmt) {
        throw new RuntimeException('Prepare failed: ' . $conn->error);
    }

    $inputLength = mb_strlen($userInput, 'UTF-8');
    $inputType = $mode === 'url' ? 'url' : 'text';
    $stmt->bind_param('ssiiss', $inputType, $classification, $riskScore, $inputLength, $version, $evidence);
    $stmt->execute();
    $scanId = $stmt->insert_id;
    $stmt->close();

    $summaryDescription = "Scan classified $classification with score $riskScore/100 (input length $inputLength)";

    $reportStmt = $conn->prepare("INSERT INTO reports (scan_id, category, description) VALUES (?, ?, ?)");
    if (!$reportStmt) {
        throw new RuntimeException('Report prepare failed: ' . $conn->error);
    }

    $reportStmt->bind_param('iss', $scanId, $category, $summaryDescription);
    $reportStmt->execute();
    $reportStmt->close();

    recordScanSummary($conn, (int) $scanId, $result);

    return $result;
}

/* ---------- Request handling ---------- */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method !== 'POST') {
    jsonResponse(405, ['success' => false, 'message' => 'Method not allowed.'], ['Allow: POST']);
}

$conn = null;
try {
    $conn = connectDatabase();
    validateCsrf();
    enforceRateLimit($conn, 'scan');

    $raw = $_POST['user_input'] ?? '';
    if (!is_string($raw)) {
        jsonResponse(400, ['success' => false, 'message' => 'Invalid input.']);
    }

    $maxLength = (int) $config['security']['max_input_length'];
    if (!mb_check_encoding($raw, 'UTF-8') || mb_strlen($raw, 'UTF-8') > $maxLength) {
        jsonResponse(400, ['success' => false, 'message' => "Input is too long. Maximum length is {$maxLength} characters."]);
    }

    if (isLikelyBadInput($raw)) {
        jsonResponse(400, ['success' => false, 'message' => 'Input contains potentially malicious code and was rejected.']);
    }

    $text = normalizeInput(sanitizeText($raw));
    if ($text === '') {
        jsonResponse(400, ['success' => false, 'message' => 'Input is empty.']);
    }

    $mode = $_POST['scan_mode'] ?? 'message';
    if (!is_string($mode) || !in_array($mode, ['message','url'],true)) jsonResponse(400, ['success'=>false,'message'=>'Invalid scan mode.']);
    if ($mode === 'url') {
        $tokens = preg_split('/\s+/', detectionNormalize($text));
        if (count($tokens)>20) jsonResponse(400,['success'=>false,'message'=>'Enter at most 20 URLs.']);
        foreach ($tokens as $token) {
            if (!preg_match('~^(?:https?://|www\.|(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:[/:?#]|$))~i', $token) || count(detectionUrls($token))!==1) {
                jsonResponse(400,['success'=>false,'message'=>'Enter HTTP(S) URLs only, one per line.']);
            }
        }
    }
    $conn->begin_transaction();
    $scan = saveScan($conn, $text, $mode);
    $conn->commit();
    $conn->close();

    jsonResponse(200, ['success' => true, 'message' => 'Scan saved successfully.'] + $scan);
} catch (Throwable $e) {
    if ($conn) { try { $conn->rollback(); $conn->close(); } catch (Throwable $ignored) {} }
    error_log('scan.php failed: ' . $e->getMessage());
    // In development only, show the real cause so setup problems (missing tables, stale seed) are visible.
    $detail = ($config['env'] === 'development') ? ' [' . get_class($e) . ': ' . $e->getMessage() . ']' : '';
    jsonResponse(500, ['success' => false, 'message' => 'Failed to process the scan.' . $detail]);
}
