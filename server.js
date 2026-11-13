// CyberNexus backend: zero dependencies, Node 18+. Run with: npm start
const http = require('http'), fs = require('fs'), path = require('path'), net = require('net'), tls = require('tls');
const dns = require('dns').promises;

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0'; // local only by default
const PUB = path.join(__dirname, 'Public');
const MIME = {'.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml'};
const err = (code, msg) => Object.assign(new Error(msg), {code});

/* ---- SSRF guard: only ever connect to public internet addresses ---- */
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const l = ip.toLowerCase();
  if (l.startsWith('::ffff:')) return isPrivate(l.slice(7));
  return l === '::1' || l === '::' || /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('ff');
}
async function safeHost(h) {
  h = String(h || '').trim().toLowerCase().replace(/\.$/, '');
  if (!net.isIP(h) && !/^[a-z0-9.-]{1,253}$/.test(h)) throw err(400, 'Enter a valid domain name.');
  const addrs = net.isIP(h) ? [{address: h}] : await dns.lookup(h, {all: true}).catch(() => { throw err(404, 'That domain could not be resolved.'); });
  if (addrs.some((a) => isPrivate(a.address))) throw err(403, 'Private or internal addresses are blocked.');
  return {host: h, ip: addrs[0].address};
}

/* ---- 1. SSL certificate ---- */
const ssl = async (q) => {
  const {host, ip} = await safeHost(q.host);
  return new Promise((resolve, reject) => {
    const s = tls.connect({host: ip, servername: host, port: 443, rejectUnauthorized: false, timeout: 8000}, () => {
      const c = s.getPeerCertificate();
      if (!c || !c.subject) { s.end(); return reject(err(502, 'No certificate was returned.')); }
      const out = {
        host, ip, authorized: s.authorized, authError: s.authorizationError ? String(s.authorizationError) : null,
        protocol: s.getProtocol(), cipher: s.getCipher() && s.getCipher().name,
        subject: c.subject.CN || JSON.stringify(c.subject), issuer: [c.issuer.O, c.issuer.CN].filter(Boolean).join(' · '),
        validFrom: c.valid_from, validTo: c.valid_to, daysLeft: Math.floor((new Date(c.valid_to) - Date.now()) / 864e5),
        san: (c.subjectaltname || '').split(', ').map((x) => x.replace('DNS:', '')).filter(Boolean),
        fingerprint: c.fingerprint256, bits: c.bits,
      };
      s.end(); resolve(out);
    });
    s.on('error', (e) => reject(err(502, 'TLS connection failed: ' + e.message)));
    s.on('timeout', () => { s.destroy(); reject(err(504, 'Connection timed out.')); });
  });
};

/* ---- 2. DNS ---- */
const R = new dns.Resolver(); R.setServers(['1.1.1.1', '8.8.8.8']);
const TYPES = {A: 'resolve4', AAAA: 'resolve6', MX: 'resolveMx', NS: 'resolveNs', TXT: 'resolveTxt', CNAME: 'resolveCname', SOA: 'resolveSoa', CAA: 'resolveCaa'};
const fmt = (x) => typeof x === 'string' ? x : Array.isArray(x) ? x.join('') : x.exchange ? x.priority + ' ' + x.exchange : x.nsname ? x.nsname + ' ' + x.hostmaster + ' serial ' + x.serial : JSON.stringify(x);
const dnsq = async (q) => {
  const name = String(q.name || '').trim().toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9.-]{1,253}$/.test(name) || !name.includes('.')) throw err(400, 'Enter a domain like example.com.');
  const records = {};
  await Promise.all(Object.entries(TYPES).map(async ([k, fn]) => {
    try { const r = await R[fn](name); records[k] = (Array.isArray(r) ? r : [r]).map(fmt); } catch {}
  }));
  return {name, records};
};

/* ---- 3. HTTP security headers ---- */
const CHECKS = [
  ['strict-transport-security', 'HSTS', 'Forces browsers to use HTTPS.', 20],
  ['content-security-policy', 'Content-Security-Policy', 'Blocks injected scripts (XSS).', 25],
  ['x-frame-options', 'X-Frame-Options', 'Stops clickjacking.', 15],
  ['x-content-type-options', 'X-Content-Type-Options', 'Stops MIME sniffing.', 10],
  ['referrer-policy', 'Referrer-Policy', 'Limits URL leakage to other sites.', 10],
  ['permissions-policy', 'Permissions-Policy', 'Restricts camera, mic and other features.', 10],
  ['cross-origin-opener-policy', 'COOP', 'Isolates the browsing context.', 10],
];
const hdr = async (q) => {
  let u;
  try { u = new URL(/^https?:\/\//i.test(q.url) ? q.url : 'https://' + q.url); } catch { throw err(400, 'Enter a valid URL.'); }
  let res;
  for (let i = 0; i < 4; i++) { // follow up to 3 redirects, re-checking every hop
    await safeHost(u.hostname);
    res = await fetch(u, {redirect: 'manual', signal: AbortSignal.timeout(8000), headers: {'user-agent': 'CyberNexus-HeaderCheck/1.0'}})
      .catch((e) => { throw err(502, 'Request failed: ' + e.message); });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) { u = new URL(loc, u); continue; }
    break;
  }
  if (res.body) res.body.cancel().catch(() => {});
  let score = 0;
  const checks = CHECKS.map(([k, label, why, pts]) => {
    const value = res.headers.get(k); if (value) score += pts;
    return {label, why, present: !!value, value: value || ''};
  });
  const leaks = ['server', 'x-powered-by'].filter((k) => res.headers.get(k)).map((k) => k + ': ' + res.headers.get(k));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  return {status: res.status, finalUrl: u.href, score, grade, checks, leaks};
};

/* ---- 5. WHOIS via RDAP (tries rdap.org first, then the registry's own server from the IANA bootstrap) ---- */
const RDAP_HEADERS = {accept: 'application/rdap+json, application/json', 'user-agent': 'Mozilla/5.0 (compatible; CyberNexus/1.0)'};
let bootstrap = null;
async function registryUrl(domain) {
  try {
    if (!bootstrap) bootstrap = await (await fetch('https://data.iana.org/rdap/dns.json', {signal: AbortSignal.timeout(8000)})).json();
    const tld = domain.split('.').pop();
    const svc = bootstrap.services.find((x) => x[0].includes(tld));
    return svc ? svc[1][0].replace(/\/?$/, '/') + 'domain/' + domain : null;
  } catch { return null; }
}
async function rdapFetch(urls) {
  let last = 0;
  for (const url of urls) {
    if (!url) continue;
    try {
      const r = await fetch(url, {headers: RDAP_HEADERS, signal: AbortSignal.timeout(10000)});
      if (r.ok) return r.json();
      if (r.status === 404) throw err(404, 'No registration record found.');
      last = r.status;
    } catch (e) { if (e.code === 404) throw e; }
  }
  throw err(502, last ? 'The registry refused the request (HTTP ' + last + '). Try again in a minute.' : 'The RDAP services are unreachable.');
}
const rdap = async (q) => {
  const v = String(q.q || '').trim().toLowerCase(); let j;
  if (net.isIP(v)) {
    if (isPrivate(v)) throw err(403, 'Private addresses have no public record.');
    j = await rdapFetch(['https://rdap.org/ip/' + v, 'https://rdap.arin.net/registry/ip/' + v]);
  } else {
    if (!/^[a-z0-9.-]{3,253}$/.test(v) || !v.includes('.')) throw err(400, 'Enter a domain like example.com.');
    j = await rdapFetch(['https://rdap.org/domain/' + v, await registryUrl(v)]);
  }
  const ev = (n) => (j.events || []).find((e) => e.eventAction === n)?.eventDate;
  const reg = (j.entities || []).find((e) => (e.roles || []).includes('registrar'));
  const created = ev('registration');
  return {
    name: j.ldhName || j.name || v, handle: j.handle, registrar: reg?.vcardArray?.[1]?.find((x) => x[0] === 'fn')?.[3],
    created, expires: ev('expiration'), updated: ev('last changed'),
    ageDays: created ? Math.floor((Date.now() - new Date(created)) / 864e5) : null,
    status: j.status || [], nameservers: (j.nameservers || []).map((n) => n.ldhName), country: j.country,
    range: j.startAddress ? j.startAddress + ' – ' + j.endAddress : null,
  };
};

/* ---- 6. File reputation (hash lookup on VirusTotal; the file itself never reaches this server) ---- */
const fileRep = async (q) => {
  const h = String(q.hash || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(h)) throw err(400, 'Expected a SHA-256 hash.');
  const key = process.env.VT_API_KEY;
  if (!key) return {hash: h, noKey: true};
  const r = await fetch('https://www.virustotal.com/api/v3/files/' + h, {headers: {'x-apikey': key}, signal: AbortSignal.timeout(10000)})
    .catch(() => { throw err(502, 'VirusTotal is unreachable.'); });
  if (r.status === 404) return {hash: h, found: false};
  if (!r.ok) throw err(502, 'VirusTotal error ' + r.status);
  const a = (await r.json()).data.attributes;
  return {hash: h, found: true, stats: a.last_analysis_stats, names: (a.names || []).slice(0, 3), type: a.type_description, size: a.size};
};

/* ---- Server: tiny rate limiter, API router, static files ---- */
const API = {ssl, dns: dnsq, headers: hdr, whois: rdap, file: fileRep};
const hits = new Map();
http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname.startsWith('/api/')) {
    const send = (c, o) => { res.writeHead(c, {'content-type': 'application/json'}); res.end(JSON.stringify(o)); };
    const ip = req.socket.remoteAddress, now = Date.now();
    const recent = (hits.get(ip) || []).filter((t) => now - t < 60000); recent.push(now); hits.set(ip, recent);
    if (recent.length > 30) return send(429, {error: 'Too many requests. Please wait a minute.'});
    const fn = API[u.pathname.slice(5)];
    if (!fn) return send(404, {error: 'Unknown tool.'});
    try { send(200, await fn(Object.fromEntries(u.searchParams))); }
    catch (e) { typeof e.code === 'number' ? send(e.code, {error: e.message}) : (console.error(e), send(500, {error: 'Server error.'})); }
    return;
  }
  const p = path.join(PUB, path.normalize(u.pathname === '/' ? 'index.html' : u.pathname));
  if (!p.startsWith(PUB)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(p, (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, {'content-type': MIME[path.extname(p)] || 'application/octet-stream'}); res.end(d);
  });
}).listen(PORT, HOST, () => console.log('CyberNexus running at http://' + HOST + ':' + PORT));