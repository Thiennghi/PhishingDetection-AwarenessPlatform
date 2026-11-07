/* Per-link inspection. Submitted links are never opened or fetched. */
(function(root) {
  'use strict';
  function urlDecode(value) {
    let out=String(value);
    for(let i=0;i<2;i++) {
      try { const next=decodeURIComponent(out); if(next===out) break; out=next; } catch { break; }
    }
    return out;
  }
  function inspectLink(url,knowledge,depth=0) {
    const E=root.DetectionEngine, u=E.parseVisibleUrl(url), checks=[];
    const ruleMap=new Map(knowledge.rules.filter(r=>r.type==='url').map(r=>[r.id,r]));
    const add=id=>{if(!checks.some(x=>x.id===id)) {const r=ruleMap.get(id);checks.push({id:r.id,label:r.label,weight:r.weight,family:r.family,sources:r.sources});}};
    let host=u?.hostname||'', recognized=false, redirectHost=null;
    const embedded=[];
    // Deliberately conservative validation for ambiguous authority syntax.
    const hostPort=u?.authority.slice(u.authority.lastIndexOf('@')+1)||'';
    const portMatch=hostPort.match(/:(\d+)$/);
    const hostValid=host.startsWith('[') ? /^\[[0-9a-f:.]+\]$/i.test(host) : /^[a-z0-9\u0080-\uFFFF-]+(?:\.[a-z0-9\u0080-\uFFFF-]+)*\.?$/i.test(host);
    const valid=!!u && hostValid && !/[\s<>\\]/.test(url) && (!portMatch || (+portMatch[1]>0 && +portMatch[1]<=65535));
    if(!valid) add('link_invalid');
    if(u) {
      const suffix=urlDecode(u.suffix).toLowerCase();
      const sensitive=/(?:^|[\/_?&=.-])(?:log-?in|sign-?in|verify|verification|password|billing|authenticate|secure-account)(?:$|[\/_?&=.-])/i.test(suffix);
      if(u.authority.includes('@')) add('link_userinfo');
      if(host.includes('%') || /^(?:0x[0-9a-f]+|\d+|0\d+\.\d+\.\d+\.\d+)$/i.test(host)) add('link_obfuscated');
      if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[') || host==='localhost' || host.endsWith('.local')) add('link_ip');
      if(u.scheme==='http') add('link_http');
      if(host.includes('xn--') || /[^\x00-\x7f]/.test(host)) add('link_idn');
      if(knowledge.shorteners.some(d=>host===d||host.endsWith('.'+d))) add('link_shortener');
      const confusables={'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y','і':'i','ј':'j','ѕ':'s','ο':'o','ρ':'p'};
      const skeleton=host.replace(/[аеорсхуіјѕορ]/g,c=>confusables[c]);
      for(const brand of knowledge.brands) {
        const known=brand.domains.some(d=>host===d||host.endsWith('.'+d));
        recognized ||= known;
        if(known) continue;
        const tokenMatch=brand.tokens.some(t=>new RegExp('(?:^|[.-])'+t+'(?:[.-]|$)','i').test(host));
        const buried=brand.domains.some(d=>host.includes(d+'.'));
        if(buried) add('link_brand_subdomain');
        if(tokenMatch) add(sensitive?'link_brand_login':'link_brand_lookalike');
        if(skeleton!==host && brand.tokens.some(t=>new RegExp('(?:^|[.-])'+t+'(?:[.-]|$)','i').test(skeleton))) add('link_confusable');
        if(!tokenMatch && sensitive && brand.tokens.some(t=>new RegExp('(?:^|[/_?&=.-])'+t+'(?:[/_?&=.-]|$)','i').test(suffix))) add('link_brand_path');
      }
      if(/\.(?:exe|scr|js|vbs|msi|bat|cmd|ps1|hta)(?:[?#]|$)/i.test(suffix)) add('link_download');
      if(/\.(?:pdf|docx?|xlsx?|jpg|png|txt)\.(?:exe|scr|js|vbs|bat|cmd|hta)(?:[?#]|$)/i.test(suffix)) add('link_double_extension');
      if(/[?&](?:password|passwd|pwd|otp|seed|private_key|cvv)=[^&#\s]+/i.test(suffix)) add('link_secret_query');
      if(/(?:double[-_]?your[-_]?money|guaranteed[-_]?(?:profit|returns?)|claim[-_]?(?:prize|lottery))/i.test(suffix) && /(?:bitcoin|crypto|deposit|fee|payment)/i.test(suffix)) add('link_scam_lure');
      if(depth<2) {
        const query=(u.suffix.split('?')[1]||'').split('#')[0];
        for(const pair of query.split('&')) {
          const equal=pair.indexOf('=');if(equal<0) continue;
          const key=urlDecode(pair.slice(0,equal)).toLowerCase();
          if(!['url','target','redirect','redirect_url','redirect_uri','next','return','returnto','continue','dest','destination'].includes(key)) continue;
          let target=urlDecode(pair.slice(equal+1));if(target.startsWith('//')) target='https:'+target;
          if(!/^https?:\/\//i.test(target)) continue;
          const child=inspectLink(target,knowledge,depth+1);
          embedded.push(target,...child.embedded_urls);
          if(child.hostname && child.hostname!==host) {add('link_redirect');redirectHost=child.hostname;}
          if(child.risk_score>=60) add('link_nested_risk');
        }
      }
    }
    // Keep weak URL traits from accumulating into a fabricated high-risk verdict.
    const highest=checks.reduce((a,b)=>b.weight>a.weight?b:a,{weight:0,family:'unknown'});
    const score=highest.weight;
    return {url,hostname:host||'(unparsed)',canonical:u?.canonical||null,valid,
      risk_score:score,verdict:score>=60?'HIGH RISK':score>=30?'SUSPICIOUS':'UNVERIFIED',
      threat_type:score>=60?(highest.family==='malware'?'DANGEROUS DOWNLOAD INDICATORS':highest.family==='scam'?'POSSIBLE SCAM':'POSSIBLE PHISHING'):'NOT CONFIRMED',
      reasons:checks,recognized_domain:recognized,embedded_destination:redirectHost,embedded_urls:[...new Set(embedded)],
      reputation_status:'NOT CHECKED',reputation_sources:[],visited:false};
  }
  function inspectLinks(text,knowledge) {
    return root.DetectionEngine.urlsFrom(root.DetectionEngine.normalize(text)).map(url=>inspectLink(url,knowledge));
  }
  function summarizeLinks(result,links) {
    const existing=new Set(result.evidence.map(x=>x.id));
    for(const link of links) {
      for(const r of link.reasons) {
        if(!existing.has(r.id)) {result.evidence.push({id:r.id,label:r.label,weight:r.weight,sources:r.sources});existing.add(r.id);}
      }
      if(link.risk_score>result.risk_score) {
        result.risk_score=link.risk_score;result.category=link.threat_type==='NOT CONFIRMED'?'Suspicious URL indicators':link.threat_type;
      }
      if(link.risk_score>=60) {
        const family=link.threat_type.includes('DOWNLOAD')?'malware':link.threat_type.includes('SCAM')?'scam':'phishing';
        result.signals[family]=Math.max(result.signals[family],link.risk_score);
      }
    }
    result.classification=result.risk_score>=60?'HIGH RISK':result.risk_score>=30?'SUSPICIOUS':'SAFE';
    result.flags=[...new Set(result.evidence.map(e=>e.label))];
    result.urls=links;result.url_count=links.length;
    return result;
  }
  root.UrlInspector={inspectLink,inspectLinks,summarizeLinks};
  if(typeof module!=='undefined'&&module.exports) module.exports=root.UrlInspector;
})(typeof window!=='undefined'?window:globalThis);
