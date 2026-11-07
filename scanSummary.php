<?php
declare(strict_types=1);

/**
 * Basic summary storage: one row in scan_summaries per scan (id, result, recommendation,
 * cited detection sources). Called by scan.php AFTER the scan and its report are saved.
 * It never changes scoring, and a failure here never breaks the scan (the table may not be
 * installed yet: import migrations/005_scan_summaries.sql).
 */

function scanRecommendation(string $classification): string {
    if ($classification === 'HIGH RISK') {
        return 'Do not click links, open attachments or share information. Report it.';
    }
    if ($classification === 'SUSPICIOUS') {
        return 'Verify the sender and destination independently before acting.';
    }
    return 'Low risk is not proof of safety. Verify unexpected requests independently.';
}

function recordScanSummary(mysqli $conn, int $scanId, array $result): void {
    try {
        $classification = (string) ($result['classification'] ?? 'SAFE');
        $score          = (int) ($result['risk_score'] ?? 0);

        // Detection sources cited by the matched rules (fixed metadata, never user text).
        $ids = [];
        foreach ((array) ($result['evidence'] ?? []) as $match) {
            foreach ((array) ($match['sources'] ?? []) as $sourceId) {
                if (is_string($sourceId) && $sourceId !== '') {
                    $ids[$sourceId] = true;
                }
            }
        }
        $sources        = mb_substr(implode(',', array_keys($ids)), 0, 255, 'UTF-8');
        $recommendation = scanRecommendation($classification);

        $find = $conn->prepare('SELECT MAX(report_id) FROM reports WHERE scan_id = ?');
        $find->bind_param('i', $scanId);
        $find->execute();
        $find->bind_result($foundReport);
        $find->fetch();
        $find->close();
        $reportId = $foundReport === null ? null : (int) $foundReport;

        $stmt = $conn->prepare(
            'INSERT INTO scan_summaries (scan_id, report_id, classification, risk_score, recommendation, source_ids)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->bind_param('iisiss', $scanId, $reportId, $classification, $score, $recommendation, $sources);
        $stmt->execute();
        $stmt->close();
    } catch (Throwable $e) {
        error_log('scan summary not stored: ' . $e->getMessage());
    }
}
