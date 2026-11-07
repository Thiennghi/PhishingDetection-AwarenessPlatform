const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {performance} = require('node:perf_hooks');
const engine = require('../detectionEngine.js');
const root = path.join(__dirname,'..');
const k = JSON.parse(fs.readFileSync(path.join(root,'data/detection-knowledge.json'),'utf8'));
const cases = JSON.parse(fs.readFileSync(path.join(__dirname,'detection-cases.json'),'utf8'));
const results = [], failures=[];
for (const c of cases) {
 const result=engine.evaluate(c.text,k);
 results.push({...c,actual:result.classification,score:result.risk_score,matched_rules:result.evidence.map(e=>e.id)});
 if(result.classification!==c.expected) failures.push(`${c.id}: expected ${c.expected}, got ${result.classification} (${result.risk_score}): ${result.evidence.map(e=>e.id)}`);
 assert(result.risk_score>=0 && result.risk_score<=100);
 assert(new Set(result.evidence.map(e=>e.id)).size===result.evidence.length);
}
assert.equal(engine.evaluate('meeting thanks team '.repeat(100)+'Send your one-time code.',k).classification,'HIGH RISK');
assert.equal(engine.evaluate('https://clean.example.test/',k,[{source_id:'test_feed'}]).risk_score,95);
assert.equal(engine.parseVisibleUrl('HTTPS://Example.test:443/login?A=1#fragment').canonical,'https://example.test/login?A=1');
assert.equal(engine.parseVisibleUrl('https://example.test/#fragment').canonical,'https://example.test/');
assert.equal(engine.evaluate('URGENT '.repeat(500),k).risk_score,8);
const durations=[];
for(let i=0;i<100;i++) {const start=performance.now();engine.evaluate(('Normal meeting report https://example.test/ ').repeat(100),k);durations.push(performance.now()-start);}
durations.sort((a,b)=>a-b);
const report={corpus:'Authored synthetic regression cases; rules were tuned using these cases. Not an independent accuracy benchmark.',version:k.version,total:cases.length,passed:cases.length-failures.length,failed:failures.length,performance:{runs:100,input_characters:('Normal meeting report https://example.test/ ').repeat(100).length,median_ms:durations[50],p95_ms:durations[95]},results};
fs.writeFileSync(path.join(__dirname,'detection-results.json'),JSON.stringify(report,null,2)+'\n');
console.log(`${report.passed}/${report.total} synthetic regression cases passed; median ${durations[50].toFixed(2)} ms; p95 ${durations[95].toFixed(2)} ms.`);
if(failures.length){console.error(failures.join('\n'));process.exitCode=1;}
