<?php
declare(strict_types=1);
/** Diagnostic: open /health.php in the browser. DELETE this file once everything works. */
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/detectionEngine.php';
header('Content-Type: text/plain; charset=utf-8');
echo "PHP " . PHP_VERSION . "\n";
try { $k = loadDetectionKnowledgeFile(); echo "OK  data/detection-knowledge.json (version {$k['version']}, " . count($k['rules']) . " rules)\n"; }
catch (Throwable $e) { echo "FAIL json file: " . $e->getMessage() . "\n"; }
try {
    $c = connectDatabase(); echo "OK  database connected via: " . activeDbSource() . "\n";
    foreach (['scans','reports','rate_limits','detection_rules','threat_indicators','community_reports','scan_summaries'] as $t) {
        try { $n = $c->query("SELECT COUNT(*) FROM `$t`")->fetch_row()[0]; echo "OK  table $t ($n rows)\n"; }
        catch (Throwable $e) { echo "FAIL table $t: missing - import the SQL file\n"; }
    }
    try { detectionKnowledge($c); echo "OK  DB rules match JSON file\n"; }
    catch (Throwable $e) { echo "FAIL rules: " . $e->getMessage() . "\n"; }
} catch (Throwable $e) { echo "FAIL database: " . $e->getMessage() . "\n"; }
