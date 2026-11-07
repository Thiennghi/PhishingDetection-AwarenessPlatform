// No packages required: tests actual frontend handlers with a minimal DOM and mock HTTP.
const {readFileSync} = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
process.chdir(path.join(__dirname, '..'));
class Element {
  constructor() {
    this.value = ''; this.textContent = ''; this.innerHTML = ''; this.children = [];
    this.style = {}; this.listeners = {}; this.parentNode = {insertBefore(){}};
    this.classes = new Set(); this.classList = {add:x=>this.classes.add(x), remove:x=>this.classes.delete(x)};
  }
  set textContent(value) {this._text=value;this.children=[];}
  get textContent() {return this._text;}
  addEventListener(name, cb) { this.listeners[name] = cb; }
  appendChild(x) { this.children.push(x); }
  append(...xs) { this.children.push(...xs); }
  replaceChildren() { this.children = []; this.innerHTML = ''; }
  focus() {}
  scrollIntoView() {}
  reset() { this.resetCalled = true; }
}
const elements = new Map();
const get = id => {if(!elements.has(id)) elements.set(id,new Element()); return elements.get(id);};
const callbacks = [], calls = [], saved = new Map();
let mode = 'success';
const sandbox = {
 console: {log(){}, warn(){}, error(){}}, FormData, Date, RegExp, Set, Map, alert: x=>alerts.push(x),
 document: { addEventListener:(name,cb)=>(name==='DOMContentLoaded' ? callbacks.push(cb) : null), getElementById:get,
   createElement:()=>new Element(), querySelectorAll:()=>[], querySelector:()=>null },
 localStorage:{getItem:k=>saved.get(k)||null,setItem:(k,v)=>saved.set(k,v)},
 fetch: async (url, options={}) => {
  calls.push({url, options});
  if(url==='csrf.php') return {ok:true,json:async()=>({token:'test-token',max_input_length:5000})};
  if(options.method==='POST') {
   if(mode==='failure') throw new Error('Network unavailable');
   return {ok:true,json:async()=>({success:true,risk_score:42,classification:'SUSPICIOUS',signals:{phishing:35,scam:7,malware:0},flags:['Server evidence'],evidence:[],detector_version:'test',message:'Saved',html:'<table>saved</table>'})};
  }
  return {ok:true,json:async()=>({success:true,html:'<table>history</table>'})};
 }
};
const alerts=[];
sandbox.window = {addEventListener(){}};
vm.createContext(sandbox);
const files=[...readFileSync('index.html','utf8').matchAll(/<script src="([^"]+)"/g)].map(m=>m[1]);
const names=new Set();
for(const file of files) {
 const source=readFileSync(file,'utf8');
 for(const match of source.matchAll(/\bfunction\s+(\w+)\s*\(/g)) {assert(!names.has(match[1]),`duplicate ${match[1]}`);names.add(match[1]);}
 vm.runInContext(source,sandbox,{filename:file});
}
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 // Scanner DOM-ready handler follows the assistant's independent initialization handler.
 callbacks.find(cb=>cb.toString().includes('csrfReady ='))(); await flush();
 assert.equal(get('awarenessTableContainerTab').children[0].children[2].children.length,10);
 get('awarenessSearch').value='password';sandbox.window.renderAwareness();assert.equal(get('awarenessTableContainerTab').children[0].children[2].children.length,1);
 get('awarenessSearch').value='nothing-matches-xyz';sandbox.window.renderAwareness();assert.equal(get('awarenessTableContainerTab').children.length,2);
 get('awarenessSearch').value='';
 sandbox.switchTab('analyze'); assert(get('analyze').classes.has('active'));
 get('messageInput').value='  verify    your account  ';
 sandbox.runAnalysis(); await flush();
 const post=calls.find(x=>x.options.method==='POST');
 assert.equal(post.url,'scan.php');assert.equal(post.options.body.get('user_input'),'verify your account');
 assert.equal(post.options.headers['X-CSRF-Token'],'test-token');
 assert.equal(get('flagContainer').children.at(-1).textContent,'Server evidence');
 assert.equal(get('riskScore').textContent,42);assert.equal(get('classificationLabel').textContent,'SUSPICIOUS');
 const before=calls.length;
 get('clearBtn').listeners.click();await flush();
 assert.equal(calls.length,before);assert.equal(get('messageInput').value,'');assert(get('resultCard').classes.has('hidden'));
 get('messageInput').value='<script>alert(1)</script>';
 sandbox.runAnalysis();await flush();assert.equal(calls.length,before);
 sandbox.displayValidationErrors(['<img src=x onerror=alert(1)>']);
 assert.equal(get('validationErrors').children.at(-1).children[0].textContent,'<img src=x onerror=alert(1)>');
 get('threatContent').value='Suspicious message requesting money';get('threatType').value='scam';
 await sandbox.handleReport({preventDefault(){}});
 const report=calls.find(x=>x.url==='report.php');assert.equal(report.options.body.get('category'),'scam');
 assert.equal(alerts.length,0);assert(get('reportForm').resetCalled);assert.equal(get('reportStatus').textContent,'Saved');
 mode='failure';get('reportForm').resetCalled=false;
 await sandbox.handleReport({preventDefault(){}});assert.equal(alerts.length,0);assert(!get('reportForm').resetCalled);
 get('messageInput').value='verify account immediately';sandbox.runAnalysis();await flush();
 assert(get('validationErrors').children[1].children.some(x=>x.textContent.includes('not saved')));
 // URL mode reaches the backend and rejects prose without issuing a request.
 mode='success';
 sandbox.loadSample('url_phishing');
 assert.equal(get('scanMode').value,'url');
 sandbox.runAnalysis();await flush();
 assert.equal(calls.filter(x=>x.url==='scan.php'&&x.options.method==='POST').at(-1).options.body.get('scan_mode'),'url');
 const beforeInvalid=calls.length;
 get('messageInput').value='this is not a URL';sandbox.runAnalysis();await flush();
 assert.equal(calls.length,beforeInvalid);
 const details=sandbox.window.DetectionEngine.evaluate('https://www.paypal.com/ https://paypal.com.attacker.test/login',sandbox.window.PhishingDataset,[],'url');
 sandbox.renderDetectionResult(details);
 assert.equal(get('urlResultsList').children.length,2);
 assert(get('urlResultsList').children[1].children[0].textContent.includes('HIGH RISK'));
 assert(get('urlResultsList').children[1].children[1].textContent.startsWith('hxxps://'));
 assert(!get('urlResultsList').children[1].children[1].href);
 const card=get('urlResultsList').children[1];card.children.at(-1).listeners.click();assert.equal(get('reportUrl').value,'https://paypal.com.attacker.test/login');assert(get('report').classes.has('active'));
 mode='success';get('threatContent').value='';await sandbox.handleReport({preventDefault(){}});assert.equal(calls.filter(x=>x.url==='report.php').at(-1).options.body.get('url'),'https://paypal.com.attacker.test/login');
 assert(!/\sonclick=/.test(readFileSync('index.html','utf8')));
 console.log('PASS: loaded scripts, no duplicate declarations, tabs, sanitized POST, CSRF header, server result, history, Clear without HTTP, script rejection, safe errors, report success/failure, local fallback.');
})().catch(e=>{console.error(e);process.exitCode=1;});
