<?php
// Run: php tests/detection.test.php. Does not need a database.
declare(strict_types=1);
require_once __DIR__ . '/../detectionEngine.php';
$knowledge = detectionKnowledge();
$cases = json_decode(file_get_contents(__DIR__ . '/detection-cases.json'), true, 512, JSON_THROW_ON_ERROR);
$results = []; $failed = 0;
foreach ($cases as $case) {
    $result = detectionEvaluate($case['text'], $knowledge);
    $results[] = ['id'=>$case['id'],'score'=>$result['risk_score'],'classification'=>$result['classification'],'rules'=>array_column($result['evidence'],'id')];
    if ($result['classification'] !== $case['expected']) {
        fwrite(STDERR, $case['id'] . ': ' . $result['classification'] . "\n"); $failed++;
    }
}
if (in_array('--json', $argv, true)) echo json_encode($results, JSON_THROW_ON_ERROR);
else echo (count($cases) - $failed) . '/' . count($cases) . " PHP regression cases passed.\n";
exit($failed ? 1 : 0);
