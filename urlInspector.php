<?php
declare(strict_types=1);
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) { http_response_code(404); exit; }
function linkDecode(string $value): string {
    for ($i=0;$i<2;$i++) { $next=rawurldecode($value); if ($next===$value || !mb_check_encoding($next,'UTF-8')) break; $value=$next; }
    return $value;
}
function inspectLink(string $url, array $knowledge, int $depth=0): array {
    $u=detectionParseUrl($url); $checks=[]; $ruleMap=[];
    foreach ($knowledge['rules'] as $rule) if ($rule['type']==='url') $ruleMap[$rule['id']]=$rule;
    $add=function(string $id) use (&$checks,$ruleMap): void {
        if (isset($checks[$id])) return; $r=$ruleMap[$id];
        $checks[$id]=['id'=>$r['id'],'label'=>$r['label'],'weight'=>$r['weight'],'family'=>$r['family'],'sources'=>$r['sources']];
    };
    $host=$u['hostname'] ?? ''; $recognized=false; $redirectHost=null; $embedded=[];
    $authority=$u['authority'] ?? ''; $at=strrpos($authority,'@'); $hostPort=$at===false?$authority:substr($authority,$at+1);
    preg_match('/:(\d+)$/',$hostPort,$port);
    $hostValid=str_starts_with($host,'[') ? preg_match('/^\[[0-9a-f:.]+\]$/i',$host) : preg_match('/^[a-z0-9\x{0080}-\x{FFFF}-]+(?:\.[a-z0-9\x{0080}-\x{FFFF}-]+)*\.?$/iu',$host);
    $valid=(bool)($u && $hostValid && !preg_match('~[\s<>\\\\]~',$url) && (!$port || ((int)$port[1]>0 && (int)$port[1]<=65535)));
    if (!$valid) $add('link_invalid');
    if ($u) {
        $suffix=strtolower(linkDecode($u['suffix']));
        $sensitive=preg_match('~(?:^|[/_?&=.-])(?:log-?in|sign-?in|verify|verification|password|billing|authenticate|secure-account)(?:$|[/_?&=.-])~i',$suffix);
        if (strpos($authority,'@')!==false) $add('link_userinfo');
        if (strpos($host,'%')!==false || preg_match('/^(?:0x[0-9a-f]+|\d+|0\d+\.\d+\.\d+\.\d+)$/i',$host)) $add('link_obfuscated');
        if (preg_match('/^(?:\d{1,3}\.){3}\d{1,3}$/',$host) || str_starts_with($host,'[') || $host==='localhost' || str_ends_with($host,'.local')) $add('link_ip');
        if ($u['scheme']==='http') $add('link_http');
        if (strpos($host,'xn--')!==false || preg_match('/[^\x00-\x7f]/',$host)) $add('link_idn');
        foreach ($knowledge['shorteners'] as $d) if ($host===$d || str_ends_with($host,'.'.$d)) { $add('link_shortener'); break; }
        $skeleton=strtr($host,['а'=>'a','е'=>'e','о'=>'o','р'=>'p','с'=>'c','х'=>'x','у'=>'y','і'=>'i','ј'=>'j','ѕ'=>'s','ο'=>'o','ρ'=>'p']);
        foreach ($knowledge['brands'] as $brand) {
            $known=false; foreach($brand['domains'] as $d) if($host===$d || str_ends_with($host,'.'.$d)) $known=true;
            $recognized=$recognized || $known; if($known) continue;
            $tokenMatch=false; $buried=false; $confusable=false; $pathBrand=false;
            foreach($brand['tokens'] as $token) {
                $pattern='~(?:^|[.-])'.preg_quote($token,'~').'(?:[.-]|$)~i';
                if(preg_match($pattern,$host)) $tokenMatch=true;
                if(preg_match($pattern,$skeleton)) $confusable=true;
                if(preg_match('~(?:^|[/_?&=.-])'.preg_quote($token,'~').'(?:[/_?&=.-]|$)~i',$suffix)) $pathBrand=true;
            }
            foreach($brand['domains'] as $d) if(strpos($host,$d.'.')!==false) $buried=true;
            if($buried) $add('link_brand_subdomain');
            if($tokenMatch) $add($sensitive?'link_brand_login':'link_brand_lookalike');
            if($skeleton!==$host && $confusable) $add('link_confusable');
            if(!$tokenMatch && $sensitive && $pathBrand) $add('link_brand_path');
        }
        if(preg_match('/\.(?:exe|scr|js|vbs|msi|bat|cmd|ps1|hta)(?:[?#]|$)/i',$suffix)) $add('link_download');
        if(preg_match('/\.(?:pdf|docx?|xlsx?|jpg|png|txt)\.(?:exe|scr|js|vbs|bat|cmd|hta)(?:[?#]|$)/i',$suffix)) $add('link_double_extension');
        if(preg_match('/[?&](?:password|passwd|pwd|otp|seed|private_key|cvv)=[^&#\s]+/i',$suffix)) $add('link_secret_query');
        if(preg_match('/(?:double[-_]?your[-_]?money|guaranteed[-_]?(?:profit|returns?)|claim[-_]?(?:prize|lottery))/i',$suffix) && preg_match('/(?:bitcoin|crypto|deposit|fee|payment)/i',$suffix)) $add('link_scam_lure');
        if($depth<2) {
            $query=explode('?', $u['suffix'],2)[1] ?? ''; $query=explode('#',$query)[0];
            foreach(explode('&',$query) as $pair) {
                $equal=strpos($pair,'='); if($equal===false) continue;
                $key=strtolower(linkDecode(substr($pair,0,$equal)));
                if(!in_array($key,['url','target','redirect','redirect_url','redirect_uri','next','return','returnto','continue','dest','destination'],true)) continue;
                $target=linkDecode(substr($pair,$equal+1)); if(str_starts_with($target,'//')) $target='https:'.$target;
                if(!preg_match('~^https?://~i',$target)) continue;
                $child=inspectLink($target,$knowledge,$depth+1);
                $embedded[]=$target; $embedded=array_merge($embedded,$child['embedded_urls']);
                if($child['hostname'] && $child['hostname']!==$host) { $add('link_redirect'); $redirectHost=$child['hostname']; }
                if($child['risk_score']>=60) $add('link_nested_risk');
            }
        }
    }
    $highest=['weight'=>0,'family'=>'unknown']; foreach($checks as $check) if($check['weight']>$highest['weight']) $highest=$check;
    $score=$highest['weight'];
    return ['url'=>$url,'hostname'=>$host ?: '(unparsed)','canonical'=>$u['canonical'] ?? null,'valid'=>$valid,
        'risk_score'=>$score,'verdict'=>$score>=60?'HIGH RISK':($score>=30?'SUSPICIOUS':'UNVERIFIED'),
        'threat_type'=>$score>=60?($highest['family']==='malware'?'DANGEROUS DOWNLOAD INDICATORS':($highest['family']==='scam'?'POSSIBLE SCAM':'POSSIBLE PHISHING')):'NOT CONFIRMED',
        'reasons'=>array_values($checks),'recognized_domain'=>$recognized,'embedded_destination'=>$redirectHost,'embedded_urls'=>array_values(array_unique($embedded)),
        'reputation_status'=>'NOT CHECKED','reputation_sources'=>[],'visited'=>false];
}
function inspectLinks(string $text,array $knowledge): array {
    return array_map(function($url) use($knowledge) {return inspectLink($url,$knowledge);},detectionUrls(detectionNormalize($text)));
}
function summarizeLinks(array $result,array $links): array {
    $ids=array_fill_keys(array_column($result['evidence'],'id'),true);
    foreach($links as $link) {
        foreach($link['reasons'] as $r) if(!isset($ids[$r['id']])) {
            $result['evidence'][]=['id'=>$r['id'],'label'=>$r['label'],'weight'=>$r['weight'],'sources'=>$r['sources']]; $ids[$r['id']]=true;
        }
        if($link['risk_score']>$result['risk_score']) { $result['risk_score']=$link['risk_score']; $result['category']=$link['threat_type']==='NOT CONFIRMED'?'Suspicious URL indicators':$link['threat_type']; }
        if($link['risk_score']>=60) {
            $family=strpos($link['threat_type'],'DOWNLOAD')!==false?'malware':(strpos($link['threat_type'],'SCAM')!==false?'scam':'phishing');
            $result['signals'][$family]=max($result['signals'][$family],$link['risk_score']);
        }
    }
    $result['classification']=$result['risk_score']>=60?'HIGH RISK':($result['risk_score']>=30?'SUSPICIOUS':'SAFE');
    $result['flags']=array_values(array_unique(array_column($result['evidence'],'label')));
    $result['urls']=$links; $result['url_count']=count($links);
    return $result;
}
function applyLinkReputation(array $links,array $hits,int $activeCount): array {
    foreach($links as &$link) {
        $link['reputation_status']=$activeCount>0?'NOT LISTED (NOT A SAFETY GUARANTEE)':'NO ACTIVE FEED';
        if(!$link['valid'] || !$link['canonical']) { $link['reputation_status']='NOT CHECKED: AMBIGUOUS URL'; continue; }
        $hash=hash('sha256',$link['canonical']);
        $embeddedHashes=[];
        foreach($link['embedded_urls'] as $target) {
            $parsed=detectionParseUrl($target);
            if($parsed) $embeddedHashes[]=hash('sha256',$parsed['canonical']);
        }
        foreach($hits as $hit) {
            if($hit['url_hash']!==$hash && !in_array($hit['url_hash'],$embeddedHashes,true)) continue;
            $nested=$hit['url_hash']!==$hash;
            $link['reputation_status']=$nested?'EMBEDDED DESTINATION MATCHED ACTIVE PHISHING RECORD':'MATCHED ACTIVE PHISHING RECORD';
            $link['reputation_sources'][]=$hit['source_id'];
            $link['risk_score']=max(95,$link['risk_score']); $link['verdict']='HIGH RISK'; $link['threat_type']=$nested?'REPORTED PHISHING DESTINATION':'REPORTED PHISHING';
            $link['reasons'][]=['id'=>'link_feed_'.$hit['source_id'],'label'=>'URL or embedded destination matched an unexpired phishing-feed record','weight'=>95,'family'=>'phishing','sources'=>[$hit['source_id']]];
        }
    }
    unset($link); return $links;
}
