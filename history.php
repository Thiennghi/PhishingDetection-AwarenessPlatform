<?php
declare(strict_types=1);

/**
 * Scan History panel (Dashboard tab).
 *
 *   GET  history.php               -> {success, html}: scans, reports and threat indicators from the database
 *   POST history.php action=reset  -> "Reset session & go home": DELETES all scans, reports, community
 *                                     reports and scan summaries from the database
 *
 * The panel also builds a live summary: scan classifications, community-report statuses (updated when an
 * administrator approves/rejects), the detection sources and the stored per-scan summaries (scan_summaries).
 *
 * A reset empties scans, reports, community_reports and scan_summaries. Reference data (detection sources,
 * rules, threat indicators) and rate-limit counters are kept. Private user-report text is never shown.
 */

require_once __DIR__ . '/bootstrap.php';

function hx(?string $value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** $rows = list of rows; every cell must already be escaped HTML. */
function historyTable(array $head, array $rows): string {
    $th = '';
    foreach ($head as $title) {
        $th .= '<th>' . hx($title) . '</th>';
    }
    $tr = '';
    foreach ($rows as $cells) {
        $tr .= '<tr><td>' . implode('</td><td>', $cells) . '</td></tr>';
    }
    return '<div class="sh-scroll"><table class="sh-table"><thead><tr>' . $th . '</tr></thead><tbody>' . $tr . '</tbody></table></div>';
}

function historySection(string $title, array $head, array $rows, bool $showCount = true): string {
    $body  = $rows ? historyTable($head, $rows) : '<p class="sh-empty">No live history recorded.</p>';
    $count = $showCount ? ' <span class="sh-count">(' . count($rows) . ')</span>' : '';
    return '<section class="sh-section"><h4 class="sh-title">' . hx($title) . $count . '</h4>' . $body . '</section>';
}

function fetchRows(mysqli $conn, string $sql): array {
    return $conn->query($sql)->fetch_all(MYSQLI_ASSOC);
}

function classBadge(string $label): string {
    $class = $label === 'HIGH RISK' ? 'high' : ($label === 'SUSPICIOUS' ? 'suspicious' : 'safe');
    return '<span class="history-badge ' . $class . '">' . hx($label) . '</span>';
}

/** Summary block: classification + community status counts, detection sources, stored summary history. */
function renderSummary(mysqli $conn): string {
    try {
        $classRows = fetchRows($conn,
            'SELECT classification, COUNT(*) AS n FROM scans GROUP BY classification');
        $communityRows = fetchRows($conn,
            'SELECT status, COUNT(*) AS n FROM community_reports GROUP BY status');
        $sources = fetchRows($conn,
            'SELECT source_id, publisher, title, reviewed_on FROM detection_sources ORDER BY publisher, source_id');
        $summaries = fetchRows($conn,
            'SELECT summary_id, scan_id, report_id, classification, risk_score, recommendation, source_ids, created_at
               FROM scan_summaries ORDER BY summary_id DESC LIMIT 50');
        $citedRows = fetchRows($conn,
            "SELECT source_ids FROM scan_summaries WHERE source_ids <> '' ORDER BY summary_id DESC LIMIT 500");
    } catch (Throwable $e) {
        error_log('history summary unavailable: ' . $e->getMessage());
        return '<p class="sh-note">Summary storage is not installed yet. Import migrations/005_scan_summaries.sql (or cyberguard_db_xampp.sql).</p>';
    }

    $classCount = ['HIGH RISK' => 0, 'SUSPICIOUS' => 0, 'SAFE' => 0];
    foreach ($classRows as $row) {
        $classCount[(string) $row['classification']] = (int) $row['n'];
    }
    $classTable = [];
    foreach ($classCount as $label => $n) {
        $classTable[] = [classBadge($label), (string) $n];
    }

    $communityCount = ['pending' => 0, 'approved' => 0, 'rejected' => 0];
    foreach ($communityRows as $row) {
        $communityCount[(string) $row['status']] = (int) $row['n'];
    }
    $communityTable = [];
    foreach ($communityCount as $status => $n) {
        $communityTable[] = [hx(ucfirst($status)), (string) $n];
    }

    $cited = [];
    foreach ($citedRows as $row) {
        foreach (explode(',', (string) $row['source_ids']) as $id) {
            if ($id !== '') {
                $cited[$id] = ($cited[$id] ?? 0) + 1;
            }
        }
    }
    $sourceTable = [];
    foreach ($sources as $row) {
        $sourceTable[] = [
            hx((string) $row['source_id']),
            hx((string) $row['publisher']),
            hx((string) $row['title']),
            hx((string) $row['reviewed_on']),
            (string) ($cited[(string) $row['source_id']] ?? 0),
        ];
    }

    $summaryTable = [];
    foreach ($summaries as $row) {
        $summaryTable[] = [
            hx((string) $row['summary_id']),
            hx((string) $row['scan_id']),
            hx($row['report_id'] === null ? '-' : (string) $row['report_id']),
            classBadge((string) $row['classification']),
            hx((string) $row['risk_score']) . '/100',
            hx((string) $row['recommendation']),
            hx($row['source_ids'] === '' ? '-' : str_replace(',', ', ', (string) $row['source_ids'])),
            hx((string) $row['created_at']),
        ];
    }

    $latest = $summaries ? '<p class="sh-reco"><strong>Latest recommendation:</strong> ' . hx((string) $summaries[0]['recommendation']) . '</p>' : '';

    return $latest
        . '<div class="grid-2">'
        . historySection('Scan classification', ['Result', 'Scans'], $classTable, false)
        . historySection('Community reports', ['Status', 'Reports'], $communityTable, false)
        . '</div>'
        . historySection('Detection sources', ['ID', 'Publisher', 'Title', 'Reviewed', 'Cited in scans'], $sourceTable)
        . historySection('Summary history', ['Summary ID', 'Scan ID', 'Report ID', 'Result', 'Score', 'Recommendation', 'Sources', 'Date'], $summaryTable);
}

function renderHistoryPanel(mysqli $conn): string {
    $scans = fetchRows($conn,
        'SELECT scan_id, classification, risk_score, input_length, detector_version, created_at
           FROM scans ORDER BY scan_id DESC LIMIT 50');

    $reports = fetchRows($conn,
        'SELECT r.report_id, r.scan_id, r.source, r.category, r.description, r.created_at, c.status
           FROM reports r LEFT JOIN community_reports c ON c.report_id = r.report_id
          ORDER BY r.report_id DESC LIMIT 50');

    $indicators = fetchRows($conn,
        'SELECT source_id, LEFT(url_hash, 12) AS hash_prefix, imported_at, expires_at
           FROM threat_indicators ORDER BY imported_at DESC LIMIT 50');

    $totals = $conn->query('SELECT (SELECT COUNT(*) FROM scans), (SELECT COUNT(*) FROM reports), (SELECT COUNT(*) FROM threat_indicators)')->fetch_row();

    $scanRows = [];
    foreach ($scans as $row) {
        $scanRows[] = [
            hx((string) $row['scan_id']),
            classBadge((string) $row['classification']),
            hx((string) $row['risk_score']) . '/100',
            hx((string) $row['input_length']),
            hx($row['detector_version'] === null ? '-' : (string) $row['detector_version']),
            hx((string) $row['created_at']),
        ];
    }

    $reportRows = [];
    foreach ($reports as $row) {
        $isUser = $row['source'] === 'user';
        $reportRows[] = [
            hx((string) $row['report_id']),
            hx($row['scan_id'] === null ? '-' : (string) $row['scan_id']),
            $isUser ? 'User report' : 'Scan summary',
            hx((string) $row['category']),
            $isUser ? '<em>Private (not shown)</em>' : hx((string) $row['description']),
            hx($isUser ? (string) ($row['status'] ?? 'pending') : '-'),
            hx((string) $row['created_at']),
        ];
    }

    $indicatorRows = [];
    foreach ($indicators as $row) {
        $indicatorRows[] = [
            hx((string) $row['source_id']),
            hx((string) $row['hash_prefix']) . '&hellip;',
            hx((string) $row['imported_at']),
            hx((string) $row['expires_at']),
        ];
    }

    return '<div class="sh-wrap">'
        . '<p class="sh-totals">Database totals: ' . (int) $totals[0] . ' scans &middot; ' . (int) $totals[1] . ' reports &middot; ' . (int) $totals[2] . ' threat indicators</p>'
        . renderSummary($conn)
        . historySection('Scans', ['Scan ID', 'Result', 'Score', 'Length', 'Detector', 'Date'], $scanRows)
        . historySection('Reports', ['Report ID', 'Scan ID', 'Type', 'Category', 'Description', 'Status', 'Date'], $reportRows)
        . historySection('Threat indicators (reference data, not cleared by reset)', ['Source', 'URL hash', 'Imported', 'Expires'], $indicatorRows)
        . '</div>';
}

/* ---------- Request handling ---------- */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method !== 'GET' && $method !== 'POST') {
    jsonResponse(405, ['success' => false, 'message' => 'Method not allowed.'], ['Allow: GET, POST']);
}

$conn = connectDatabase();

try {
    startSecureSession();
    enforceRateLimit($conn, 'history', 60, 60);

    if ($method === 'POST') {
        validateCsrf();
        if (($_POST['action'] ?? '') !== 'reset') {
            jsonResponse(400, ['success' => false, 'message' => 'Unknown action.']);
        }
        // community_reports and scan_summaries are removed by their ON DELETE CASCADE foreign keys.
        $conn->begin_transaction();
        $conn->query('DELETE FROM reports');
        $conn->query('DELETE FROM scans');
        $conn->commit();
        // DDL commits implicitly, so it runs after the transaction; failing here (no ALTER privilege) is harmless.
        foreach (['reports', 'scans', 'scan_summaries'] as $table) {
            try { $conn->query("ALTER TABLE `$table` AUTO_INCREMENT = 1"); } catch (Throwable $ignored) {}
        }
    }

    $html = renderHistoryPanel($conn);
    $conn->close();

    jsonResponse(200, ['success' => true, 'html' => $html]);
} catch (Throwable $e) {
    try { $conn->rollback(); } catch (Throwable $ignored) {}
    error_log('history.php failed: ' . $e->getMessage());
    jsonResponse(500, ['success' => false, 'message' => 'Could not load the scan history.']);
}
