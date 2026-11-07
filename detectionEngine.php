<?php
declare(strict_types=1);
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) { http_response_code(404); exit; }

require_once __DIR__ . '/urlInspector.php';

/** Reads data/detection-knowledge.json safely (case-sensitive hosts, BOM, unreadable file). Never passes false to json_decode. */
function loadDetectionKnowledgeFile(): array {
    static $cache = null;
    if ($cache !== null) return $cache;
    $json = false;
    $embedded = __DIR__ . '/detection_knowledge_data.php';
    if (is_file($embedded)) {
        $json = include $embedded;          // returns the JSON text; no dependency on the data/ folder
    }
    if (!is_string($json) || $json === '') {
        $path = __DIR__ . '/data/detection-knowledge.json';
        $json = is_file($path) ? @file_get_contents($path) : false;
    }
    if (!is_string($json) || $json === '') {
        throw new RuntimeException('Detection data not found. Upload detection_knowledge_data.php to the same folder as scan.php (or the data/ folder).');
    }
    if (strncmp($json, "\xEF\xBB\xBF", 3) === 0) $json = substr($json, 3);
    $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($data) || !isset($data['version'], $data['rules'])) {
        throw new RuntimeException('data/detection-knowledge.json is incomplete (truncated upload?).');
    }
    return $cache = $data;
}

function detectionKnowledge(?mysqli $conn = null): array {
    $knowledge = loadDetectionKnowledgeFile();
    if ($conn) {
        $result = $conn->query('SELECT rule_id, dataset_version, rule_json FROM detection_rules ORDER BY rule_id');
        $rules = [];
        while ($row = $result->fetch_assoc()) {
            if ($row['dataset_version'] !== $knowledge['version']) throw new RuntimeException('Detection data version mismatch; import matching seed');
            if (!isset($row['rule_json']) || !is_string($row['rule_json']) || trim($row['rule_json']) === '') {
                throw new RuntimeException('Detection rule "' . ($row['rule_id'] ?? '?') . '" has empty JSON in the database. Re-import cyberguard_db_infinityfree.sql (InfinityFree) or cyberguard_db.sql (XAMPP).');
            }
            $rule = json_decode($row['rule_json'], true, 512, JSON_THROW_ON_ERROR);
            $rules[$rule['id']] = $rule;
        }
        $result->free();
        // Preserve canonical order and fail closed on missing/stale or modified rules.
        foreach ($knowledge['rules'] as &$rule) {
            if (!isset($rules[$rule['id']]) || $rules[$rule['id']] != $rule) throw new RuntimeException('Detection seed out of sync');
            $rule = $rules[$rule['id']];
        }
        unset($rule);
        if (count($rules) !== count($knowledge['rules'])) throw new RuntimeException('Unexpected detection rule count');
    }
    return $knowledge;
}
function detectionNormalize(string $text): string {
    $text = preg_replace_callback('/[\x{FF01}-\x{FF5E}]/u', function ($m) { return mb_chr(mb_ord($m[0], 'UTF-8') - 0xFEE0, 'UTF-8'); }, $text);
    $text = preg_replace('/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}\x{FEFF}]/u', '', $text);
    $text = str_replace(['’','‘','[.]','(.)'], ["'","'",'.','.'], $text);
    $text = preg_replace_callback('~hxxps?://~i', function ($m) { return strlen($m[0]) === 8 ? 'https://' : 'http://'; }, $text);
    return trim(preg_replace('/\s+/u', ' ', $text));
}
function detectionUrls(string $text): array {
    preg_match_all('~(?:https?://|www\.)[^\s<>"\']+|(?:^|[\s(])(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:[/:?\#][^\s<>"\']*)?~i', $text, $matches);
    $urls = [];
    foreach ($matches[0] as $url) {
        $url = preg_replace('/[.,;!?]+$/', '', trim($url));
        foreach ([['(',')'],['[',']'],['{','}']] as [$open,$close]) {
            while (str_ends_with($url,$close) && substr_count($url,$close)>substr_count($url,$open)) $url=substr($url,0,-1);
        }
        if (!preg_match('~^https?://~i', $url)) $url = 'https://' . $url;
        if (!in_array($url, $urls, true)) $urls[] = $url;
    }
    return $urls;
}
function detectionParseUrl(string $url): ?array {
    if (!preg_match('~^(https?)://([^/?\#]+)(.*)$~i', $url, $m)) return null;
    $authority = $m[2];
    $at = strrpos($authority, '@');
    $hostPort = $at === false ? $authority : substr($authority, $at + 1);
    $host = mb_strtolower(preg_replace('/:\d+$/', '', rtrim($hostPort, '.')), 'UTF-8');
    if ($host === '') return null;
    $suffix = explode('#', $m[3] ?: '/')[0];
    if ($suffix === '') $suffix = '/';
    preg_match('/:\d+$/', $hostPort, $pm);
    $port = $pm[0] ?? '';
    $scheme = strtolower($m[1]);
    if (($scheme === 'https' && $port === ':443') || ($scheme === 'http' && $port === ':80')) $port = '';
    $canonical = $scheme . '://' . $host . $port . ($suffix[0] === '?' ? '/' : '') . $suffix;
    return ['hostname'=>$host,'authority'=>$authority,'suffix'=>$suffix,'scheme'=>$scheme,'canonical'=>$canonical];
}
function detectionFeatures(string $raw, array $knowledge): array {
    $text = detectionNormalize($raw); $urls = detectionUrls($text); $features = [];
    if (preg_match('~[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}\x{FEFF}]|hxxps?:|\[\.\]|\(\.\)~iu', $raw)) $features['obfuscated'] = true;
    if ($urls) $features['url_present'] = true;
    foreach ($urls as $url) {
        $u = detectionParseUrl($url); if (!$u) continue;
        $host = $u['hostname'];
        foreach ($knowledge['shorteners'] as $d) if ($host === $d || str_ends_with($host, '.' . $d)) $features['shortener'] = true;
        if (preg_match('/^(?:\d{1,3}\.){3}\d{1,3}$/', $host) || str_starts_with($host, '[')) $features['ip_host'] = true;
        if (strpos($u['authority'], '@') !== false) $features['userinfo'] = true;
        if (strpos($host, 'xn--') !== false || preg_match('/[^\x00-\x7F]/', $host)) $features['punycode'] = true;
        if (strpos($host, '%') !== false || strpos($u['authority'], '\\') !== false) $features['encoded_host'] = true;
        if ($u['scheme'] === 'http') $features['http'] = true;
        if (preg_match('/\.(?:exe|scr|js|vbs|msi|bat|cmd|ps1|hta)(?:[?#]|$)/i', $u['suffix'])) $features['executable'] = true;
        foreach ($knowledge['brands'] as $brand) {
            $recognized = false;
            foreach ($brand['domains'] as $d) if ($host === $d || str_ends_with($host, '.' . $d)) $recognized = true;
            if (!$recognized) foreach ($brand['tokens'] as $token) {
                if (preg_match('/(?:^|[.-])' . preg_quote($token, '/') . '(?:[.-]|$)/i', $host)) $features['brand_mismatch'] = true;
            }
        }
    }
    return [$text,$features,$urls];
}
function detectionActiveMatches(string $pattern, string $sentence): bool {
    if (preg_match_all('~' . str_replace('~','\\~',$pattern) . '~i', $sentence, $matches, PREG_OFFSET_CAPTURE) === false) throw new RuntimeException('Invalid detector pattern');
    foreach ($matches[0] as $match) {
        $before = substr($sentence, max(0, $match[1] - 45), min(45, $match[1]));
        if (!preg_match("/(?:\\bnever\\b|\\bdo not\\b|\\bdon't\\b|\\bwon't\\b|\\bwill not\\b|\\bavoid\\b|\\bno need to\\b)[^,;:.!?]{0,32}$/i", $before)) return true;
    }
    return false;
}
function detectionEvaluate(string $raw, array $knowledge, array $reputation = [], string $mode = 'message'): array {
    [$text,$features,$urls] = detectionFeatures($raw,$knowledge);
    $sentences = preg_split('/(?:[.!?]\s+|\n+)/', $text);
    $matches = []; $groups = []; $families = ['phishing'=>0,'scam'=>0,'malware'=>0];
    $floor = 0; $strongest = -1; $dominant = 'No strong indicators';
    $record = function (array $rule) use (&$matches,&$features,&$groups,&$floor,&$strongest,&$dominant): void {
        $matches[] = ['id'=>$rule['id'],'label'=>$rule['label'],'weight'=>$rule['weight'],'sources'=>$rule['sources']];
        $features[$rule['id']] = true;
        if (!isset($groups[$rule['group']]) || $groups[$rule['group']]['weight'] < $rule['weight']) $groups[$rule['group']] = ['weight'=>$rule['weight'],'family'=>$rule['family']];
        $strength = $rule['min_score'] ?? $rule['weight'];
        if ($strength > $strongest) { $strongest = $strength; $dominant = $rule['label']; }
        $floor = max($floor,$rule['min_score'] ?? 0);
    };
    foreach ($knowledge['rules'] as $rule) {
        if ($rule['type'] === 'feature' && isset($features[$rule['feature']])) $record($rule);
        if ($rule['type'] !== 'text') continue;
        foreach ($sentences as $sentence) {
            $any = false;
            foreach ($rule['any_regex'] as $pattern) if (detectionActiveMatches($pattern,$sentence)) $any = true;
            $all = true;
            foreach ($rule['all_regex'] ?? [] as $pattern) if (!detectionActiveMatches($pattern,$sentence)) $all = false;
            if ($any && $all) { $record($rule); break; }
        }
    }
    foreach ($knowledge['rules'] as $rule) {
        if ($rule['type'] !== 'combination') continue;
        $all = true;
        foreach ($rule['all_signals'] as $set) {
            $any = false;
            foreach ($set as $signal) if (isset($features[$signal])) $any = true;
            if (!$any) $all = false;
        }
        if ($all) $record($rule);
    }
    $total = 0;
    foreach ($groups as $group) { $families[$group['family']] += $group['weight']; $total += $group['weight']; }
    foreach ($reputation as $hit) {
        $matches[] = ['id'=>'reputation_'.$hit['source_id'],'label'=>'URL listed in an unexpired phishing feed','weight'=>95,'sources'=>[$hit['source_id']]];
        $floor = max($floor,95); $families['phishing'] = max($families['phishing'],95); $dominant = 'Phishing-feed URL match';
    }
    $score = min(100,max($floor,$total));
    $result = ['success'=>true,'risk_score'=>$score,'classification'=>$score >= $knowledge['thresholds']['high'] ? 'HIGH RISK' : ($score >= $knowledge['thresholds']['suspicious'] ? 'SUSPICIOUS' : 'SAFE'),
        'category'=>$dominant,'detector_version'=>$knowledge['version'],'evidence'=>$matches,
        'signals'=>array_map(function($v) { return min(100,$v); }, $families),
        'flags'=>array_column($matches,'label'),'url_count'=>count($urls),'limitations'=>$knowledge['limitations'],'reputation_checked'=>false];
    if ($mode === 'url') {
        $result['risk_score']=0; $result['evidence']=[]; $result['category']='No strong indicators';
        $result['signals']=['phishing'=>0,'scam'=>0,'malware'=>0];
    }
    return summarizeLinks($result,inspectLinks($raw,$knowledge));
}
function detectionReputation(mysqli $conn, string $text, array $knowledge): array {
    $hits = [];
    $stmt = $conn->prepare('SELECT source_id FROM threat_indicators WHERE url_hash = ? AND expires_at > UTC_TIMESTAMP()');
    $candidates = detectionUrls(detectionNormalize($text));
    foreach (inspectLinks($text,$knowledge) as $link) foreach ($link['embedded_urls'] as $embedded) $candidates[]=$embedded;
    foreach (array_unique($candidates) as $url) {
        $parsed = detectionParseUrl($url); if (!$parsed) continue;
        $hash = hash('sha256',$parsed['canonical']);
        $stmt->bind_param('s',$hash); $stmt->execute(); $stmt->bind_result($source);
        while ($stmt->fetch()) $hits[$hash . ':' . $source] = ['source_id'=>$source,'url_hash'=>$hash];
        $stmt->free_result();
    }
    $stmt->close();
    return array_values($hits);
}
