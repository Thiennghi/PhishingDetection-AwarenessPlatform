const cp=require('node:child_process'), fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict');
const probe=cp.spawnSync('php',['--version']);
if(probe.error) {console.log('SKIP: PHP CLI unavailable; PHP syntax and JS/PHP parity are NOT verified.');process.exit(0);}
const result=cp.spawnSync('php',[path.join(__dirname,'detection.test.php'),'--json'],{encoding:'utf8'});
if(result.status!==0) throw new Error(result.stderr || result.stdout);
const engine=require('../detectionEngine.js');
const k=JSON.parse(fs.readFileSync(path.join(__dirname,'../data/detection-knowledge.json'),'utf8'));
const cases=JSON.parse(fs.readFileSync(path.join(__dirname,'detection-cases.json'),'utf8'));
const php=JSON.parse(result.stdout);
for(let i=0;i<cases.length;i++) {
 const r=engine.evaluate(cases[i].text,k);
 assert.deepEqual(php[i],{id:cases[i].id,score:r.risk_score,classification:r.classification,rules:r.evidence.map(e=>e.id)});
}
console.log('PASS: identical JS/PHP scores, classifications and rules for '+cases.length+' cases.');
const urlCheck=cp.spawnSync('php',[path.join(__dirname,'urls.test.php')],{encoding:'utf8'});
if(urlCheck.status!==0) throw new Error(urlCheck.stderr||urlCheck.stdout);
console.log(urlCheck.stdout.trim());
