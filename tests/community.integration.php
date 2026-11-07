<?php
/** Run ONLY on a disposable test database with all migrations installed:
 * APP_ENV=development php tests/community.integration.php
 * Uses a transaction and rolls back its fixtures. Requires mysqli + mbstring.
 */
declare(strict_types=1);
require_once __DIR__.'/../bootstrap.php';
require_once __DIR__.'/../communityReports.php';
if(PHP_SAPI!=='cli' || $config['env']!=='development') throw new RuntimeException('Development CLI only.');
function check(bool $ok,string $message):void {if(!$ok)throw new RuntimeException($message);}
$conn=connectDatabase();$conn->begin_transaction();
try {
 $url='https://community-fixture.test/'.bin2hex(random_bytes(12));
 $link=communityUrl($url);check($link!==null,'URL accepted');
 try {communityUrl('javascript:alert(1)');throw new RuntimeException('Unsafe scheme accepted');}catch(InvalidArgumentException $expected){}
 $knowledge=json_decode(file_get_contents(__DIR__.'/../data/detection-knowledge.json'),true,512,JSON_THROW_ON_ERROR);
 $stmt=$conn->prepare("INSERT INTO reports (source,category,description) VALUES ('user','Financial Scam','Private test report')");$stmt->execute();$id=$stmt->insert_id;$stmt->close();
 $stmt=$conn->prepare('INSERT INTO community_reports (report_id,submitted_url,url_hash) VALUES (?,?,?)');$stmt->bind_param('iss',$id,$url,$link['hash']);$stmt->execute();$stmt->close();
 $links=inspectLinks($url.' https://neutral-fixture.test/',$knowledge);
 check(applyCommunityReputation($conn,$links)[0]['risk_score']<95,'Pending report must not affect score');
 $conn->query("UPDATE community_reports SET status='approved',reviewed_at=UTC_TIMESTAMP(),expires_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY) WHERE report_id=".$id);
 $results=applyCommunityReputation($conn,$links);
 check($results[0]['risk_score']===95 && $results[0]['threat_type']==='REVIEWED SCAM','Approval category and score');
 check($results[1]['risk_score']<95,'Unrelated link isolation');
 $embedded=inspectLinks('https://redirect-fixture.test/?url='.rawurlencode($url),$knowledge);
 check(applyCommunityReputation($conn,$embedded)[0]['risk_score']===95,'Embedded destination checked');
 $conn->query("UPDATE community_reports SET expires_at=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND) WHERE report_id=".$id);
 check(applyCommunityReputation($conn,$links)[0]['risk_score']<95,'Expired record ignored');
 $conn->query("UPDATE community_reports SET status='rejected',expires_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY) WHERE report_id=".$id);
 check(applyCommunityReputation($conn,$links)[0]['risk_score']<95,'Rejected record ignored');
 echo "PASS: pending/approved/expired/rejected isolation and embedded matches.\n";
} finally {$conn->rollback();$conn->close();}
