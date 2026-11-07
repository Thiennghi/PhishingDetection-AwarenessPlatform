/* Source-backed heuristics. Shared rule payload: data/detection-knowledge.json.
 * No network requests, script execution, or probability/accuracy claims. */
(function (root) {
  'use strict';
  function normalize(text) {
    return String(text).replace(/[\uFF01-\uFF5E]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xFEE0))
      .replace(/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g, '')
      .replace(/[’‘]/g, "'").replace(/hxxps?:\/\//gi, s => s.length === 8 ? 'https://' : 'http://')
      .replace(/\[\.\]|\(\.\)/g, '.').replace(/\s+/g, ' ').trim();
  }
  function urlsFrom(text) {
    const found = [];
    const pattern = /(?:https?:\/\/|www\.)[^\s<>"']+|(?:^|[\s(])(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:[/:?#][^\s<>"']*)?/gi;
    for (const match of text.matchAll(pattern)) {
      let url = match[0].trim().replace(/[.,;!?]+$/, '');
      for (const [open,close] of [['(',')'],['[',']'],['{','}']]) {
        while(url.endsWith(close) && url.split(close).length>url.split(open).length) url=url.slice(0,-1);
      }
      if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
      if (!found.includes(url)) found.push(url);
    }
    return found;
  }
  function parseVisibleUrl(url) {
    const match = url.match(/^(https?):\/\/([^/?#]+)(.*)$/i);
    if (!match) return null;
    const authority = match[2];
    const hostPort = authority.slice(authority.lastIndexOf('@') + 1);
    const hostname = hostPort.replace(/:\d+$/, '').replace(/\.$/, '').toLowerCase();
    if (!hostname) return null;
    const suffix = (match[3] || '/').split('#')[0] || '/';
    // Conservative normalization: preserve path/query case and escapes; no redirect following.
    const port = /:\d+$/.exec(hostPort)?.[0] || '';
    const canonicalPort = (match[1].toLowerCase() === 'https' && port === ':443') || (match[1].toLowerCase() === 'http' && port === ':80') ? '' : port;
    const canonical = match[1].toLowerCase() + '://' + hostname + canonicalPort + (suffix.startsWith('?') ? '/' : '') + suffix;
    return {hostname, authority, suffix, scheme:match[1].toLowerCase(), canonical};
  }
  function featuresFor(raw, knowledge) {
    const text = normalize(raw), features = new Set(), urls = urlsFrom(text);
    if (/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]|hxxps?:|\[\.\]|\(\.\)/i.test(raw)) features.add('obfuscated');
    if (urls.length) features.add('url_present');
    for (const url of urls) {
      const u = parseVisibleUrl(url); if (!u) continue;
      const host = u.hostname;
      if (knowledge.shorteners.some(d => host === d || host.endsWith('.'+d))) features.add('shortener');
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[')) features.add('ip_host');
      if (u.authority.includes('@')) features.add('userinfo');
      if (host.includes('xn--') || /[^\x00-\x7F]/.test(host)) features.add('punycode');
      if (host.includes('%') || u.authority.includes('\\')) features.add('encoded_host');
      if (u.scheme === 'http') features.add('http');
      if (/\.(?:exe|scr|js|vbs|msi|bat|cmd|ps1|hta)(?:[?#]|$)/i.test(u.suffix)) features.add('executable');
      for (const brand of knowledge.brands) {
        const recognized = brand.domains.some(d => host === d || host.endsWith('.'+d));
        if (!recognized && brand.tokens.some(t => new RegExp('(?:^|[.-])'+t+'(?:[.-]|$)','i').test(host))) features.add('brand_mismatch');
      }
    }
    return {text,features,urls};
  }
  function activeMatches(pattern, sentence) {
    const matches = [...sentence.matchAll(new RegExp(pattern, 'gi'))];
    return matches.some(m => {
      const before = sentence.slice(Math.max(0,m.index-45),m.index);
      // Scope negation to the nearby preceding clause, not the whole message.
      return !/(?:\bnever\b|\bdo not\b|\bdon't\b|\bwon't\b|\bwill not\b|\bavoid\b|\bno need to\b)[^,;:.!?]{0,32}$/i.test(before);
    });
  }
  function evaluate(raw, knowledge, reputation = [], mode = 'message') {
    const {text,features,urls} = featuresFor(raw,knowledge);
    const sentences = text.split(/(?:[.!?]\s+|\n+)/);
    const matches = [], groups = {}, families = {phishing:0,scam:0,malware:0};
    let floor = 0, dominant = 'No strong indicators', strongest = -1;
    const record = rule => {
      matches.push({id:rule.id,label:rule.label,weight:rule.weight,sources:rule.sources});
      features.add(rule.id);
      const old = groups[rule.group];
      if (!old || old.weight < rule.weight) groups[rule.group] = {weight:rule.weight,family:rule.family};
      if ((rule.min_score || rule.weight) > strongest) { strongest=rule.min_score||rule.weight; dominant=rule.label; }
      floor = Math.max(floor,rule.min_score||0);
    };
    for (const rule of knowledge.rules) {
      if (rule.type === 'feature' && features.has(rule.feature)) record(rule);
      if (rule.type === 'text' && sentences.some(s => rule.any_regex.some(p => activeMatches(p,s)) && (rule.all_regex||[]).every(p=>activeMatches(p,s)))) record(rule);
    }
    for (const rule of knowledge.rules) {
      if (rule.type === 'combination' && rule.all_signals.every(set=>set.some(x=>features.has(x)))) record(rule);
    }
    for (const group of Object.values(groups)) families[group.family] += group.weight;
    // Reputation entries are only supplied by server-side indexed lookup, never by user POST.
    for (const hit of reputation) {
      matches.push({id:'reputation_'+hit.source_id,label:'URL listed in an unexpired phishing feed',weight:95,sources:[hit.source_id]});
      floor=Math.max(floor,95); families.phishing=Math.max(families.phishing,95); dominant='Phishing-feed URL match';
    }
    const score = Math.min(100,Math.max(floor,Object.values(groups).reduce((sum,g)=>sum+g.weight,0)));
    const result = {success:true,risk_score:score,classification:score>=knowledge.thresholds.high?'HIGH RISK':score>=knowledge.thresholds.suspicious?'SUSPICIOUS':'SAFE',
      category:dominant,detector_version:knowledge.version,evidence:matches,
      signals:Object.fromEntries(Object.entries(families).map(([k,v])=>[k,Math.min(100,v)])),
      flags:matches.map(x=>x.label),url_count:urls.length,
      limitations:knowledge.limitations, reputation_checked:false};
    if(mode==='url') { result.risk_score=0; result.evidence=[]; result.category='No strong indicators'; result.signals={phishing:0,scam:0,malware:0}; }
    return root.UrlInspector ? root.UrlInspector.summarizeLinks(result,root.UrlInspector.inspectLinks(raw,knowledge)) : result;
  }
  root.DetectionEngine = {evaluate,normalize,urlsFrom,parseVisibleUrl};
  if (typeof module !== 'undefined' && module.exports) { module.exports = root.DetectionEngine; require('./urlInspector.js'); }
})(typeof window !== 'undefined' ? window : globalThis);
