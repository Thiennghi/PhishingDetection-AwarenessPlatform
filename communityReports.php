<?php
declare(strict_types=1);
require_once __DIR__ . '/detectionEngine.php';
/** Structured URL validation shared by submission and reviewer approval. No network requests. */
function communityUrl(string $raw): ?array {
    $url = trim($raw);
    if ($url === '') return null;
    if (strlen($url) > 2048 || !preg_match('~^https?://[^\s<>]+$~i', $url)) throw new InvalidArgumentException('Use a complete HTTP(S) URL, at most 2048 bytes, without spaces.');
    $knowledge = loadDetectionKnowledgeFile();
    $link = inspectLink($url, $knowledge);
    if (!$link['valid'] || !$link['canonical']) throw new InvalidArgumentException('This URL is ambiguous. Check its spelling before reporting it.');
    return ['url'=>$url,'hash'=>hash('sha256',$link['canonical'])];
}
/** Exact matches only. Pending/rejected/expired records do not participate. */
function applyCommunityReputation(mysqli $conn, array $links): array {
    $stmt=$conn->prepare("SELECT r.category FROM community_reports c JOIN reports r ON r.report_id=c.report_id WHERE c.url_hash=? AND c.status='approved' AND c.expires_at>UTC_TIMESTAMP() ORDER BY c.reviewed_at DESC LIMIT 1");
    foreach ($links as &$link) {
        if (!$link['valid']) continue;
        $candidates=array_merge([$link['url']],$link['embedded_urls']);
        foreach ($candidates as $index=>$url) {
            $parsed=detectionParseUrl($url); if (!$parsed) continue;
            $hash=hash('sha256',$parsed['canonical']);$stmt->bind_param('s',$hash);$stmt->execute();
            $row=$stmt->get_result()->fetch_assoc(); if (!$row) continue;
            $family=$row['category']==='Financial Scam'?'scam':($row['category']==='Malicious URL / Link'?'malware':'phishing');
            $label=$family==='scam'?'SCAM':($family==='malware'?'DANGEROUS DOWNLOAD / URL':'PHISHING');
            $link['risk_score']=max(95,$link['risk_score']);$link['verdict']='HIGH RISK';
            $link['threat_type']='REVIEWED '.$label.($index?' DESTINATION':'');
            $link['reputation_status']='MATCHED ADMIN-REVIEWED COMMUNITY REPORT';
            $link['reasons'][]=['id'=>'community_'.$family,'label'=>'URL or visible embedded destination matches an active administrator-approved report','weight'=>95,'family'=>$family,'sources'=>[]];
            break;
        }
    }
    unset($link);$stmt->close();return $links;
}
