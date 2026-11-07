const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
class E {constructor(){this.children=[];this.listeners={};this.value='';this.classes=new Set();this.classList={add:v=>this.classes.add(v),remove:v=>this.classes.delete(v)};}addEventListener(k,f){this.listeners[k]=f;}append(...nodes){this.children.push(...nodes);}appendChild(n){this.children.push(n);}replaceChildren(){this.children=[];}focus(){}querySelector(){return new E();}}
const els=new Map(),get=id=>{if(!els.has(id))els.set(id,new E());return els.get(id);};
const calls=[];let authenticated=false;let status='pending';
const sandbox={FormData,console,document:{getElementById:get,createElement:()=>new E()},fetch:async(url,options={})=>{
 calls.push({url,options});if(url==='csrf.php')return{ok:true,json:async()=>({token:'csrf-test'})};
 const action=options.body?.get('action');
 if(action==='login')authenticated=true;
 if(action==='approve')status='approved';
 if(action==='reject')status='rejected';
 if(action==='logout')authenticated=false;
 if(!authenticated&&action!=='logout')return{ok:false,json:async()=>({success:false,message:'Unauthorized'})};
 return{ok:true,json:async()=>action?({success:true,message:'Saved'}):({success:true,reports:[{report_id:7,category:'Financial Scam',description:'<script>unsafe</script>',submitted_url:'https://fixture.test/?x=<img>',status,review_note:''}]})};
}};
vm.createContext(sandbox);vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../admin.js'),'utf8'),sandbox);
const flush=()=>new Promise(r=>setImmediate(r));
(async()=>{
 await flush();get('username').value='admin';get('password').value='example';
 await get('adminLogin').listeners.submit({preventDefault(){},target:new E()});
 assert.equal(get('password').value,'');assert(get('loginPanel').classes.has('hidden'));
 let card=get('reviewList').children[0];assert.equal(card.children[3].textContent,'<script>unsafe</script>');assert(!card.children[2].href);assert(card.children[2].textContent.startsWith('hxxps'));
 let buttons=card.children.at(-1);await buttons.children[0].listeners.click();assert(!calls.some(c=>c.options.body?.get('action')==='approve'));
 card.children[5].value='Verified independently using supporting evidence.';await buttons.children[0].listeners.click();
 const approve=calls.find(c=>c.options.body?.get('action')==='approve');assert.equal(approve.options.headers['X-CSRF-Token'],'csrf-test');assert.equal(approve.options.body.get('report_id'),'7');
 card=get('reviewList').children[0];card.children[5].value='Incorrect report after further investigation.';await card.children.at(-1).children[1].listeners.click();assert.equal(status,'rejected');
 await get('logout').listeners.click();assert.equal(get('reviewList').children.length,0);assert(get('reviewPanel').classes.has('hidden'));
 console.log('PASS: admin authentication UI, safe report rendering, review note validation, approval/rejection requests with CSRF, and logout clearing.');
})().catch(e=>{console.error(e);process.exitCode=1;});
