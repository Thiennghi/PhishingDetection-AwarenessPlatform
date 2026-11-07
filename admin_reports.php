<?php
declare(strict_types=1);
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/auth.php';
require_once __DIR__.'/communityReports.php';
$method=$_SERVER['REQUEST_METHOD']??'GET';
if (!in_array($method,['GET','POST'],true)) jsonResponse(405,['success'=>false,'message'=>'Method not allowed.'],['Allow: GET, POST']);
$conn=null;
try {
    $conn=connectDatabase();
    $action=$_POST['action']??'';
    if ($method==='POST' && $action==='login') {
        validateCsrf();
        $user=$_POST['username']??'';$pass=$_POST['password']??'';
        if(!is_string($user)||!is_string($pass)||strlen($user)>100||strlen($pass)>1024||!loginAdmin($conn,$user,$pass)) jsonResponse(401,['success'=>false,'message'=>'Login failed or temporarily rate limited.']);
        jsonResponse(200,['success'=>true]);
    }
    $auth=requireAdmin();
    if($method==='GET') {
        $rows=$conn->query("SELECT r.report_id,r.category,r.description,r.created_at,c.submitted_url,c.status,c.review_note,c.reviewed_at,c.expires_at FROM community_reports c JOIN reports r ON r.report_id=c.report_id ORDER BY (c.status='pending') DESC,r.report_id DESC LIMIT 100")->fetch_all(MYSQLI_ASSOC);
        $counts=['pending'=>0,'approved'=>0,'rejected'=>0];
        foreach($conn->query('SELECT status,COUNT(*) n FROM community_reports GROUP BY status')->fetch_all(MYSQLI_ASSOC) as $c){if(isset($counts[$c['status']]))$counts[$c['status']]=(int)$c['n'];}
        jsonResponse(200,['success'=>true,'reports'=>$rows,'counts'=>$counts]);
    }
    if ($auth==='session') validateCsrf();
    if($action==='logout') {startSecureSession();$_SESSION=[];session_regenerate_id(true);jsonResponse(200,['success'=>true]);}
    $id=filter_var($_POST['report_id']??'',FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
    $note=$_POST['note']??'';
    if(!$id || !in_array($action,['approve','reject'],true) || !is_string($note) || mb_strlen(trim($note))<5 || mb_strlen($note)>1000) jsonResponse(400,['success'=>false,'message'=>'Provide a valid report, decision, and review note (5–1000 characters).']);
    $conn->begin_transaction();
    $stmt=$conn->prepare('SELECT submitted_url FROM community_reports WHERE report_id=? FOR UPDATE');$stmt->bind_param('i',$id);$stmt->execute();$row=$stmt->get_result()->fetch_assoc();$stmt->close();
    if(!$row){$conn->rollback();jsonResponse(404,['success'=>false,'message'=>'Report not found.']);}
    $hash=null;
    if($action==='approve') {
        try{$link=communityUrl((string)$row['submitted_url']);}catch(InvalidArgumentException $e){$conn->rollback();jsonResponse(400,['success'=>false,'message'=>$e->getMessage()]);}
        if(!$link){$conn->rollback();jsonResponse(400,['success'=>false,'message'=>'A message-only report cannot become a URL indicator.']);}
        $hash=$link['hash'];
    }
    $status=$action==='approve'?'approved':'rejected';
    $stmt=$conn->prepare("UPDATE community_reports SET status=?,review_note=?,reviewed_at=UTC_TIMESTAMP(),expires_at=IF(?='approved',DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY),NULL),url_hash=COALESCE(?,url_hash) WHERE report_id=?");
    $stmt->bind_param('ssssi',$status,$note,$status,$hash,$id);$stmt->execute();$stmt->close();
    $conn->commit();jsonResponse(200,['success'=>true,'message'=>'Report '.$status.'.']);
} catch(Throwable $e) {
    if($conn){try{$conn->rollback();}catch(Throwable $ignored){}}
    error_log('admin_reports.php: '.$e->getMessage());jsonResponse(500,['success'=>false,'message'=>'Review could not be completed. Check server setup and migration 004.']);
}
