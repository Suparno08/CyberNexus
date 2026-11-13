const $=s=>document.getElementById(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function pick(t){document.querySelectorAll('.tab').forEach(b=>b.setAttribute('aria-selected',b.dataset.t===t));document.querySelectorAll('.tool').forEach(d=>d.hidden=d.id!=='t-'+t)}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>pick(b.dataset.t));

/* ---------- Link checker ---------- */
const BRANDS={paypal:'paypal.com',google:'google.com',microsoft:'microsoft.com',apple:'apple.com',amazon:'amazon.com',facebook:'facebook.com',netflix:'netflix.com',instagram:'instagram.com',whatsapp:'whatsapp.com',linkedin:'linkedin.com',dropbox:'dropbox.com',binance:'binance.com',sbi:'sbi.co.in',hdfc:'hdfcbank.com',icici:'icicibank.com'};
const SHORT=['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rb.gy','shorturl.at'];
const BADTLD=['zip','mov','xyz','top','tk','ml','ga','cf','gq','click','work','support','country','kim','loan','icu','buzz','rest'];
const WORDS=['login','signin','verify','secure','account','update','password','confirm','banking','wallet','suspend','unlock','invoice','payment','recover','alert'];
const SLD=['co','com','org','net','gov','ac'];
function regDomain(h){const p=h.split('.');if(p.length>=3&&p[p.length-1].length===2&&SLD.includes(p[p.length-2]))return p.slice(-3).join('.');return p.slice(-2).join('.')}
function checkUrl(raw){
 let s=raw.trim(),f=[],sc=0;
 if(!s)return null;
 if(!/^[a-z][a-z0-9+.-]*:\/\//i.test(s))s='http://'+s;
 let u;try{u=new URL(s)}catch(e){return{err:'That doesn’t look like a valid link.'}}
 const add=(pts,m,t)=>{sc+=pts;f.push({t,m})};
 const h=u.hostname.toLowerCase(),rd=regDomain(h),tld=h.split('.').pop();
 if(u.protocol==='http:')add(15,'Uses plain HTTP, so traffic is not encrypted.','warn');
 else if(u.protocol==='https:')f.push({t:'ok',m:'Uses HTTPS (this alone does not prove a site is safe).'});
 else add(25,'Unusual protocol: '+u.protocol,'bad');
 if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h)||h.includes(':')||/^0x/i.test(h))add(35,'Host is a raw IP address instead of a domain name.','bad');
 if(h.includes('xn--'))add(30,'Punycode domain: may mimic another site with look-alike characters.','bad');
 if(u.username||u.password||s.includes('@'))add(30,'Contains “@” or credentials; the real destination may be hidden.','bad');
 const sub=h.split('.').length-rd.split('.').length;
 if(sub>=3)add(15,'Many subdomains ('+sub+') are a common way to bury the real domain.','warn');
 if((rd.match(/-/g)||[]).length>=2)add(12,'Several hyphens in the domain name.','warn');
 if(BADTLD.includes(tld))add(15,'“.'+tld+'” is a TLD often abused in scams.','warn');
 if(SHORT.includes(rd))add(20,'URL shortener hides the final destination.','warn');
 if(u.port&&!['80','443'].includes(u.port))add(12,'Non-standard port '+u.port+'.','warn');
 if(s.length>100)add(8,'Very long URL ('+s.length+' characters).','warn');
 if(/%[0-9a-f]{2}/i.test(u.pathname+u.search)&&(s.match(/%[0-9a-f]{2}/gi)||[]).length>5)add(8,'Heavy percent-encoding can hide content.','warn');
 const hit=WORDS.filter(w=>(h+u.pathname).toLowerCase().includes(w));
 if(hit.length)add(Math.min(20,6*hit.length),'Sensitive keywords: '+hit.slice(0,4).join(', ')+'.','warn');
 const norm=h.replace(/1/g,'l').replace(/0/g,'o').replace(/3/g,'e').replace(/5/g,'s');
 for(const[b,real]of Object.entries(BRANDS)){
  if((h.includes(b)||norm.includes(b))&&rd!==real&&!rd.endsWith('.'+real)){
   add(35,'Mentions “'+b+'” but the real domain is '+rd+', not '+real+'.','bad');break}}
 if(/(^|\.)(\d)/.test(rd.split('.')[0])&&/[a-z]/.test(rd.split('.')[0])&&/\d/.test(rd.split('.')[0])&&f.every(x=>!x.m.includes('Mentions')))add(5,'Digits mixed into the domain name.','warn');
 sc=Math.min(100,sc);
 return{sc,f,host:h,rd}
}
function showUrl(){
 const r=checkUrl($('u').value),el=$('ures');el.classList.add('on');
 if(!r){el.innerHTML='<p class="note">Enter a link first.</p>';return}
 if(r.err){el.innerHTML='<div class="verdict v-warn">'+esc(r.err)+'</div>';return}
 const c=r.sc>=50?['v-bad','Likely phishing','Strong warning signs. Do not enter any details.']:r.sc>=20?['v-warn','Suspicious','Some warning signs. Verify before clicking.']:['v-safe','No obvious red flags','Still verify the sender if you were sent this link.'];
 const ic={bad:'⛔',warn:'⚠️',ok:'✅'};
 el.innerHTML='<div class="verdict '+c[0]+'"><span class="score">'+r.sc+'</span><div>'+c[1]+'<small>'+c[2]+'</small></div></div><ul class="list">'+r.f.map(x=>'<li><b>'+ic[x.t]+'</b><span>'+esc(x.m)+'</span></li>').join('')+'</ul><p class="note">Domain read as <b>'+esc(r.rd)+'</b>. Risk score is 0–100 (higher is riskier). This is a structural check only; it can’t see page content or live blocklists.</p>'}
$('ugo').onclick=showUrl;$('u').onkeydown=e=>{if(e.key==='Enter')showUrl()};

/* ---------- IP checker ---------- */
function parse4(s){const m=s.split('.');if(m.length!==4)return null;const o=[];for(const x of m){if(!/^(0|[1-9]\d{0,2})$/.test(x)||+x>255)return null;o.push(+x)}return o}
function parse6(s){
 if(!/^[0-9a-f:.]+$/i.test(s)||(s.match(/::/g)||[]).length>1)return null;
 let tail=null;if(s.includes('.')){const i=s.lastIndexOf(':'),v=parse4(s.slice(i+1));if(!v)return null;s=s.slice(0,i+1)+((v[0]<<8|v[1]).toString(16))+':'+((v[2]<<8|v[3]).toString(16))}
 let g;if(s.includes('::')){const[a,b]=s.split('::'),A=a?a.split(':'):[],B=b?b.split(':'):[];if(A.length+B.length>7)return null;g=[...A,...Array(8-A.length-B.length).fill('0'),...B]}else g=s.split(':');
 if(g.length!==8||g.some(x=>!/^[0-9a-f]{1,4}$/i.test(x)))return null;return g.map(x=>parseInt(x,16))}
function cls4(o){const[a,b]=o;
 if(a===0)return['“This network” (0.0.0.0/8)','Not routable'];
 if(a===10||(a===172&&b>=16&&b<=31)||(a===192&&b===168))return['Private (RFC 1918)','Used inside home and office networks; not reachable from the internet.'];
 if(a===127)return['Loopback','Refers to your own device (localhost).'];
 if(a===169&&b===254)return['Link-local (APIPA)','Self-assigned when DHCP fails.'];
 if(a===100&&b>=64&&b<=127)return['Carrier-grade NAT (100.64/10)','Shared address space used by ISPs.'];
 if(a>=224&&a<=239)return['Multicast','Used for one-to-many delivery.'];
 if(a>=240)return['Reserved / broadcast','Not valid as a public host address.'];
 if((a===192&&b===0&&o[2]===2)||(a===198&&b===51&&o[2]===100)||(a===203&&b===0&&o[2]===113))return['Documentation range','Reserved for examples and docs.'];
 if(a===192&&b===88&&o[2]===99)return['6to4 relay (deprecated)',''];
 return['Public','Routable on the internet. Ownership and location need a WHOIS or geo lookup.']}
function showIp(){
 const s=$('i').value.trim(),el=$('ires');el.classList.add('on');
 if(!s){el.innerHTML='<p class="note">Enter an address first.</p>';return}
 const o=parse4(s);let rows=[],type,desc;
 if(o){const c=cls4(o);type=c[0];desc=c[1];const n=((o[0]*256+o[1])*256+o[2])*256+o[3];
  rows=[['Version','IPv4'],['Type',type],['Class',o[0]<128?'A':o[0]<192?'B':o[0]<224?'C':o[0]<240?'D (multicast)':'E (reserved)'],['Integer',n],['Hex','0x'+n.toString(16).toUpperCase().padStart(8,'0')],['Binary',o.map(x=>x.toString(2).padStart(8,'0')).join('.')],['Reverse DNS',o.slice().reverse().join('.')+'.in-addr.arpa']]}
 else{const g=parse6(s);if(!g){el.innerHTML='<div class="verdict v-warn">Not a valid IPv4 or IPv6 address.<small>IPv4 looks like 203.0.113.7 with four numbers from 0 to 255.</small></div>';return}
  const f=g.map(x=>x.toString(16).padStart(4,'0')).join(':');
  type=g.every((x,i)=>i<7?x===0:x===1)?'Loopback (::1)':g.every(x=>x===0)?'Unspecified (::)':(g[0]&0xffc0)===0xfe80?'Link-local (fe80::/10)':(g[0]&0xfe00)===0xfc00?'Unique local (fc00::/7)':(g[0]>>8)===0xff?'Multicast (ff00::/8)':(g[0]===0x2001&&g[1]===0x0db8)?'Documentation (2001:db8::/32)':(g[0]&0xe000)===0x2000?'Global unicast':'Other / reserved';
  desc=/Global/.test(type)?'Routable on the internet.':'Not a public internet address.';
  rows=[['Version','IPv6'],['Type',type],['Expanded',f],['Reverse DNS',f.replace(/:/g,'').split('').reverse().join('.')+'.ip6.arpa']]}
 const pub=type==='Public'||type==='Global unicast';
 el.innerHTML='<div class="verdict '+(pub?'v-warn':'v-safe')+'"><span class="score">'+(pub?'🌐':'🏠')+'</span><div>'+esc(type)+'<small>'+esc(desc)+'</small></div></div><div class="kv">'+rows.map(r=>'<span>'+esc(r[0])+'</span><span>'+esc(r[1])+'</span>').join('')+'</div><p class="note">Runs entirely in your browser, so there is no geolocation or reputation lookup. For those, try AbuseIPDB or a WHOIS service.</p>'}
$('igo').onclick=showIp;$('i').onkeydown=e=>{if(e.key==='Enter')showIp()};

/* ---------- Password tester ---------- */
const COMMON=['password','123456','qwerty','letmein','admin','welcome','iloveyou','abc123','monkey','dragon','football','login','passw0rd','111111'];
$('p').oninput=function(){
 const v=this.value,el=$('pres');
 if(!v){el.innerHTML='<p class="note">Start typing to see an estimate.</p>';return}
 let pool=0;if(/[a-z]/.test(v))pool+=26;if(/[A-Z]/.test(v))pool+=26;if(/\d/.test(v))pool+=10;if(/[^a-zA-Z0-9]/.test(v))pool+=32;
 let bits=v.length*Math.log2(pool||1);const f=[];
 const low=v.toLowerCase();
 if(COMMON.some(c=>low.includes(c))){bits=Math.min(bits,20);f.push(['⛔','Contains a very common password or pattern.'])}
 if(/(.)\1{2,}/.test(v)){bits*=.8;f.push(['⚠️','Repeated characters weaken it.'])}
 if(/(abc|123|qwe|asd|789)/i.test(v)){bits*=.85;f.push(['⚠️','Contains a keyboard or number sequence.'])}
 if(v.length<12)f.push(['⚠️','Shorter than 12 characters. Length matters most.']);else f.push(['✅','Good length ('+v.length+' characters).']);
 if(pool<62)f.push(['⚠️','Mix in upper, lower, digits and symbols, or use a long passphrase.']);
 bits=Math.round(bits);
 const secs=Math.pow(2,bits)/2/1e10;
 const t=secs<1?'instantly':secs<60?Math.round(secs)+' seconds':secs<3600?Math.round(secs/60)+' minutes':secs<86400?Math.round(secs/3600)+' hours':secs<3.15e7?Math.round(secs/86400)+' days':secs<3.15e9?Math.round(secs/3.15e7)+' years':'centuries+';
 const lvl=bits<36?['Weak','#ff6478']:bits<60?['Fair','#ffb95a']:bits<80?['Strong','#6fe3a6']:['Excellent','#6fe3a6'];
 el.innerHTML='<div class="verdict" style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.15)"><span class="score" style="color:'+lvl[1]+'">'+bits+'</span><div>'+lvl[0]+' · about '+bits+' bits<small>Offline guessing at 10 billion tries/second: '+t+'</small></div></div><div class="bar"><i style="width:'+Math.min(100,bits/90*100)+'%;background:'+lvl[1]+'"></i></div><ul class="list">'+f.map(x=>'<li><b>'+x[0]+'</b><span>'+esc(x[1])+'</span></li>').join('')+'</ul><p class="note">An estimate only. Use a password manager and unique passwords for every account.</p>'};
$('p').dispatchEvent(new Event('input'));

/* ---------- Hashing ---------- */
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
function md5(bytes){
 const K=[],S=[7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21];
 for(let i=0;i<64;i++)K[i]=Math.floor(Math.abs(Math.sin(i+1))*4294967296)>>>0;
 const n=bytes.length,len=((n+8>>6)+1)<<6,b=new Uint8Array(len);b.set(bytes);b[n]=128;
 const dv=new DataView(b.buffer);dv.setUint32(len-8,n<<3>>>0,true);dv.setUint32(len-4,Math.floor(n/536870912),true);
 let a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
 for(let o=0;o<len;o+=64){
  let A=a0,B=b0,C=c0,D=d0;
  for(let i=0;i<64;i++){
   let F,g;
   if(i<16){F=(B&C)|(~B&D);g=i}else if(i<32){F=(D&B)|(~D&C);g=(5*i+1)%16}else if(i<48){F=B^C^D;g=(3*i+5)%16}else{F=C^(B|~D);g=(7*i)%16}
   F=(F+A+K[i]+dv.getUint32(o+g*4,true))>>>0;
   A=D;D=C;C=B;
   const s=S[(i>>4)*4+(i%4)];
   B=(B+((F<<s)|(F>>>(32-s))))>>>0;
  }
  a0=(a0+A)>>>0;b0=(b0+B)>>>0;c0=(c0+C)>>>0;d0=(d0+D)>>>0;
 }
 const out=new DataView(new ArrayBuffer(16));[a0,b0,c0,d0].forEach((v,i)=>out.setUint32(i*4,v,true));
 return hex(out.buffer);
}

/* ---------- Helpers for the server-backed tools ---------- */
const api=async(p,q)=>{let r;
 try{r=await fetch('/api/'+p+'?'+new URLSearchParams(q))}catch{throw Error('Can’t reach the CyberNexus server. Start it with “npm start”.')}
 const j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.error||'Request failed ('+r.status+')');return j};
const host=v=>{try{return new URL(/^[a-z]+:\/\//i.test(v)?v:'https://'+v).hostname}catch{return v.trim()}};
const V=(c,t,s)=>'<div class="verdict v-'+c+'"><span class="score">'+({safe:'✅',warn:'⚠️',bad:'⛔'}[c])+'</span><div>'+esc(t)+'<small>'+esc(s||'')+'</small></div></div>';
const KV=r=>'<div class="kv">'+r.filter(x=>x[1]!=null&&x[1]!=='').map(x=>'<span>'+esc(x[0])+'</span><span>'+esc(x[1])+'</span>').join('')+'</div>';
const dt=d=>d?new Date(d).toISOString().slice(0,10):'';
const topEl=document.querySelector('.top'),tabs=document.querySelector('.tabs');
const mk=(id,name,title,desc,body)=>{
 tabs.insertAdjacentHTML('beforeend','<button class="tab" role="tab" data-t="'+id+'" aria-selected="false">'+name+'</button>');
 topEl.insertAdjacentHTML('beforeend','<div class="tool glass" id="t-'+id+'" hidden><h3>'+title+'</h3><p>'+desc+'</p>'+body+'<div class="res"></div></div>');
 tabs.lastElementChild.onclick=()=>pick(id);return $('t-'+id)};
const inputRow=(ph,btn)=>'<div class="row"><input placeholder="'+ph+'" autocomplete="off" spellcheck="false"><button class="go">'+btn+'</button></div>';
const wire=(t,fn)=>{const i=t.querySelector('input'),r=t.querySelector('.res');
 const run=async()=>{if(!i.value.trim())return;r.className='res on';r.innerHTML='<p class="note">Working…</p>';
  try{r.innerHTML=await fn(i.value)}catch(e){r.innerHTML=V('bad','Couldn’t complete the check',e.message)}};
 t.querySelector('.go').onclick=run;i.onkeydown=e=>{if(e.key==='Enter')run()}};

/* ---------- 1. SSL certificate checker ---------- */
wire(mk('ssl','SSL checker','SSL certificate checker','See who issued a site’s HTTPS certificate, when it expires and which TLS version it uses.',inputRow('example.com','Check')),async v=>{
 const j=await api('ssl',{host:host(v)});
 const c=j.daysLeft<0?['bad','Certificate expired',-j.daysLeft+' days ago']:!j.authorized?['bad','Certificate not trusted',j.authError]:j.daysLeft<14?['warn','Expires very soon',j.daysLeft+' days left']:['safe','Valid certificate',j.daysLeft+' days left'];
 return V(...c)+KV([['Issued to',j.subject],['Issuer',j.issuer],['Valid from',dt(j.validFrom)],['Valid until',dt(j.validTo)],['Protocol',j.protocol],['Cipher',j.cipher],['Key size',j.bits&&j.bits+' bits'],['Alt names',j.san.slice(0,8).join('\n')],['SHA-256',j.fingerprint],['Server IP',j.ip]])});

/* ---------- 2. DNS lookup ---------- */
wire(mk('dns','DNS lookup','DNS lookup','Fetch A, AAAA, MX, NS, TXT, CNAME, SOA and CAA records through public resolvers.',inputRow('example.com','Lookup')),async v=>{
 const j=await api('dns',{name:host(v)}),e=Object.entries(j.records);
 if(!e.length)return V('warn','No records found','Check the spelling of the domain.');
 const spf=(j.records.TXT||[]).join(' ').toLowerCase().includes('v=spf1');
 return (j.records.MX&&!spf?V('warn',e.length+' record types found','Mail is set up but there is no SPF record (email spoofing risk).'):V('safe',e.length+' record types found',spf?'SPF record present.':''))+KV(e.map(([k,x])=>[k,x.join('\n')]))});

/* ---------- 3. HTTP security headers ---------- */
wire(mk('headers','Security headers','HTTP security headers checker','Grade a site’s response headers against modern browser-hardening practice.',inputRow('https://example.com','Scan')),async v=>{
 const j=await api('headers',{url:v}),c=j.score>=75?'safe':j.score>=45?'warn':'bad';
 return '<div class="verdict v-'+c+'"><span class="score">'+j.grade+'</span><div>'+j.score+'/100 · HTTP '+j.status+'<small>'+esc(j.finalUrl)+'</small></div></div><ul class="list">'+
  j.checks.map(x=>'<li><b>'+(x.present?'✅':'⚠️')+'</b><span><strong>'+esc(x.label)+'</strong> — '+esc(x.present?x.value.slice(0,90):'missing. '+x.why)+'</span></li>').join('')+
  j.leaks.map(l=>'<li><b>ℹ️</b><span>Exposes '+esc(l)+'</span></li>').join('')+'</ul>'});

/* ---------- 4. Hash generator ---------- */
const ht=mk('hash','Hash generator','Hash generator','Create MD5 and SHA checksums of any text. Everything is computed in your browser.','<div class="row"><input placeholder="Type or paste text…" autocomplete="off" spellcheck="false"></div>');
const hr=ht.querySelector('.res');
ht.querySelector('input').oninput=async e=>{
 const b=new TextEncoder().encode(e.target.value),rows=[['MD5',md5(b)]];
 for(const a of['SHA-1','SHA-256','SHA-384','SHA-512'])rows.push([a,hex(await crypto.subtle.digest(a,b))]);
 hr.className='res on';hr.innerHTML=KV(rows)+'<p class="note">Click a hash to copy it. MD5 and SHA-1 are broken for security use; prefer SHA-256 or stronger.</p>'};
hr.onclick=e=>{if(e.target.matches('.kv span:nth-child(even)'))navigator.clipboard?.writeText(e.target.textContent)};

/* ---------- 5. WHOIS / domain lookup (RDAP) ---------- */
wire(mk('whois','WHOIS lookup','WHOIS / domain lookup','Registration details for a domain or IP address, fetched over RDAP (the modern WHOIS).',inputRow('example.com or 8.8.8.8','Look up')),async v=>{
 const j=await api('whois',{q:host(v)}),young=j.ageDays!=null&&j.ageDays<30;
 return (j.ageDays==null?'':V(young?'warn':'safe',young?'Very new domain':'Established domain',j.ageDays+' days old'+(young?'. New domains are common in phishing.':'')))+
  KV([['Name',j.name],['Registrar',j.registrar],['Created',dt(j.created)],['Expires',dt(j.expires)],['Updated',dt(j.updated)],['Status',j.status.join('\n')],['Nameservers',(j.nameservers||[]).join('\n')],['Range',j.range],['Country',j.country],['Handle',j.handle]])});

/* ---------- 6. File reputation checker ---------- */
const ft=mk('file','File reputation','File reputation checker','Pick a file: it’s hashed in your browser (never uploaded) and its SHA-256 is checked against VirusTotal.','<div class="row"><input type="file"></div>');
ft.querySelector('input').onchange=async e=>{
 const f=e.target.files[0],r=ft.querySelector('.res');if(!f)return;r.className='res on';
 if(f.size>150e6){r.innerHTML=V('warn','File too large','The limit is 150 MB.');return}
 r.innerHTML='<p class="note">Hashing…</p>';
 try{
  const h=hex(await crypto.subtle.digest('SHA-256',await f.arrayBuffer())),j=await api('file',{hash:h});
  let t;
  if(j.noKey)t=V('warn','Hash ready, but no scanner key is set','Set VT_API_KEY on the server for automatic results, or use the link below.');
  else if(!j.found)t=V('warn','Never seen by VirusTotal','Unknown doesn’t mean safe. Be cautious.');
  else{const s=j.stats,bad=s.malicious+s.suspicious;t=V(bad>3?'bad':bad?'warn':'safe',bad?bad+' engines flagged this file':'No engines flagged this file',(s.harmless+s.undetected)+' engines found nothing')}
  r.innerHTML=t+KV([['File',f.name],['Size',f.size+' bytes'],['Type',j.type],['Names seen',(j.names||[]).join('\n')],['SHA-256',h]])+'<p class="note"><a class="lk" target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/'+h+'">Open on VirusTotal ↗</a></p>';
 }catch(err){r.innerHTML=V('bad','Check failed',err.message)}};

/* ---------- Live results while typing (link + IP checkers work offline, so no server load) ---------- */
$('u').addEventListener('input',()=>{const v=$('u').value.trim();v.includes('.')?showUrl():$('ures').classList.remove('on')});
$('i').addEventListener('input',()=>{const v=$('i').value.trim();parse4(v)||parse6(v)?showIp():$('ires').classList.remove('on')});


/* ---------- Scroll to the tools section and open a tool ---------- */
function openTool(t){pick(t);document.querySelector('.tpanel').scrollIntoView({behavior:'smooth',block:'start'});setTimeout(()=>{const i=document.querySelector('#t-'+t+' input');if(i&&i.type!=='file')i.focus({preventScroll:true})},600)}