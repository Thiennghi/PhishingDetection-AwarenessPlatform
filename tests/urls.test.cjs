const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const engine=require('../detectionEngine.js');
const root=path.join(__dirname,'..');
const k=JSON.parse(fs.readFileSync(path.join(root,'data/detection-knowledge.json'),'utf8'));
const cases=[
['nested_brand','https://paypal.com.attacker.test/login','HIGH RISK','POSSIBLE PHISHING'],
['at_sign','https://paypal.com@attacker.test/login','HIGH RISK','POSSIBLE PHISHING'],
['typo_login','https://paypa1.test/login','HIGH RISK','POSSIBLE PHISHING'],
['brand_verify','https://microsoft-security.test/verify','HIGH RISK','POSSIBLE PHISHING'],
['doc_exe','https://files.example.test/invoice.pdf.exe','HIGH RISK','DANGEROUS DOWNLOAD INDICATORS'],
['image_exe','https://files.example.test/photo.jpg.scr','HIGH RISK','DANGEROUS DOWNLOAD INDICATORS'],
['encoded_exe','https://files.example.test/invoice.pdf%2eexe','HIGH RISK','DANGEROUS DOWNLOAD INDICATORS'],
['scam_lure','https://offer.example.test/double-your-money?payment=bitcoin','HIGH RISK','POSSIBLE SCAM'],
['secret','https://portal.example.test/login?password=example','HIGH RISK','POSSIBLE PHISHING'],
['code','https://portal.example.test/?otp=123456','HIGH RISK','POSSIBLE PHISHING'],
['redirect_bad','https://redirect.example.test/?url=https%3A%2F%2Fpaypal.com.attacker.test%2Flogin','HIGH RISK','POSSIBLE PHISHING'],
['redirect_double_encoded','https://redirect.example.test/?next=https%253A%252F%252Fpaypal.com.attacker.test%252Flogin','HIGH RISK','POSSIBLE PHISHING'],
['cyrillic','https://pаypal.test/login','HIGH RISK','POSSIBLE PHISHING'],
['no_scheme','paypal.com.attacker.test/login','HIGH RISK','POSSIBLE PHISHING'],
['defanged','hxxps://paypal[.]com.attacker[.]test/login','HIGH RISK','POSSIBLE PHISHING'],
['official','https://www.paypal.com/login','UNVERIFIED','NOT CONFIRMED'],
['ms_official','https://login.microsoftonline.com/','UNVERIFIED','NOT CONFIRMED'],
['ordinary','https://example.com/','UNVERIFIED','NOT CONFIRMED'],
['shortener','https://bit.ly/example','UNVERIFIED','NOT CONFIRMED'],
['http','http://example.com/','UNVERIFIED','NOT CONFIRMED'],
['ipv4','http://192.0.2.1/','UNVERIFIED','NOT CONFIRMED'],
['ipv6','http://[::1]/','UNVERIFIED','NOT CONFIRMED'],
['bare_ipv6','http://[::1]','UNVERIFIED','NOT CONFIRMED'],
['punycode','https://xn--bcher-kva.example/','UNVERIFIED','NOT CONFIRMED'],
['brand_article','https://research.example.test/articles/paypal','UNVERIFIED','NOT CONFIRMED'],
['brand_query','https://research.example.test/?q=paypal','UNVERIFIED','NOT CONFIRMED'],
['normal_redirect','https://redirect.example.test/?next=https%3A%2F%2Fexample.com%2F','UNVERIFIED','NOT CONFIRMED'],
['exe','https://downloads.example.test/app.exe','SUSPICIOUS','NOT CONFIRMED'],
['typo_no_login','https://paypa1.test/','SUSPICIOUS','NOT CONFIRMED'],
['numeric','http://2130706433/','SUSPICIOUS','NOT CONFIRMED'],
['encoded_host','https://%70aypal.test/','SUSPICIOUS','NOT CONFIRMED'],
['bad_port','https://example.com:99999/','SUSPICIOUS','NOT CONFIRMED'],
['bracketed','(https://example.com/page)','UNVERIFIED','NOT CONFIRMED'],
['path_parentheses','https://example.com/article_(example)','UNVERIFIED','NOT CONFIRMED'],
];
const result=[];
for(const [id,text,verdict,type] of cases) {
 const r=engine.evaluate(text,k,[],'url'),link=r.urls[0];
 assert(link,id+' extracted');assert.equal(link.verdict,verdict,id);assert.equal(link.threat_type,type,id);
 assert.equal(link.visited,false);assert.equal(link.reputation_status,'NOT CHECKED');
 assert.equal(r.risk_score,link.risk_score,id+' same overall score');
 result.push({id,text,verdict:link.verdict,type:link.threat_type,score:link.risk_score,hostname:link.hostname});
}
const mixed=engine.evaluate('https://www.paypal.com/\nhttps://paypal.com.attacker.test/login',k,[],'url');
assert.equal(mixed.urls.length,2);assert.equal(mixed.urls[0].verdict,'UNVERIFIED');assert.equal(mixed.urls[1].verdict,'HIGH RISK');
assert.equal(mixed.risk_score,80);
assert.equal(engine.evaluate('https://example.com/',k,[],'url').urls[0].recognized_domain,false);
assert.equal(engine.evaluate('https://www.paypal.com/',k,[],'url').urls[0].recognized_domain,true);
assert.equal(engine.urlsFrom('http://[::1]')[0],'http://[::1]');
assert.equal(engine.urlsFrom('https://example.com/article_(example)')[0],'https://example.com/article_(example)');
fs.writeFileSync(path.join(__dirname,'url-results.json'),JSON.stringify({version:k.version,synthetic:true,passed:cases.length,total:cases.length,results:result},null,2)+'\n');
console.log(`PASS: ${cases.length} URL cases, per-link isolation, URL-only scoring, non-clicking inspection and balanced URL extraction.`);
