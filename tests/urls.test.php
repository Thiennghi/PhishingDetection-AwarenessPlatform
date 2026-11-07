<?php
declare(strict_types=1);
require_once __DIR__ . '/../detectionEngine.php';
$k=detectionKnowledge();
$cases=json_decode(file_get_contents(__DIR__.'/url-results.json'),true,512,JSON_THROW_ON_ERROR)['results'];
$results=[];
foreach($cases as $case) {
    $r=detectionEvaluate($case['text'],$k,[],'url'); $link=$r['urls'][0];
    foreach(['verdict','hostname'] as $field) if($link[$field]!==$case[$field]) throw new RuntimeException($case['id'].' differs: '.$field);
    if($link['risk_score']!==$case['score'] || $link['threat_type']!==$case['type']) throw new RuntimeException($case['id'].' differs: verdict/score');
    $results[]=['id'=>$case['id'],'score'=>$link['risk_score'],'verdict'=>$link['verdict'],'hostname'=>$link['hostname']];
}
$links=inspectLinks('https://example.com/ https://other.test/',$k);
$hits=[['source_id'=>'openphish','url_hash'=>hash('sha256','https://example.com/')]];
$checked=applyLinkReputation($links,$hits,1);
if($checked[0]['risk_score']!==95 || $checked[1]['risk_score']!==0) throw new RuntimeException('Reputation leaked across links');
$nested=inspectLinks('https://redirect.test/?url=https%3A%2F%2Fexample.com%2F',$k);
$checked=applyLinkReputation($nested,$hits,1);
if($checked[0]['risk_score']!==95 || $checked[0]['threat_type']!=='REPORTED PHISHING DESTINATION') throw new RuntimeException('Nested reputation missing');
if(applyLinkReputation($links,[],0)[0]['reputation_status']!=='NO ACTIVE FEED') throw new RuntimeException('Empty feed status incorrect');
echo in_array('--json',$argv,true)?json_encode($results,JSON_THROW_ON_ERROR):count($cases)." PHP URL cases passed, including isolated/embedded reputation checks.\n";
