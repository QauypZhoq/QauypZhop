'use strict';
// Қалқан — passive website security checker. No dependencies, Node.js >= 18.
const http = require('http'), https = require('https'), tls = require('tls');
const dns = require('dns'), net = require('net'), fs = require('fs'), path = require('path');

const PORT = process.env.PORT || 3000;
const TIMEOUT = 8000;
const PUB = path.join(__dirname, 'public');

/* ---------- SSRF protection: never connect to private / internal addresses ---------- */
const blocked = new net.BlockList();
[['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],
 ['172.16.0.0',12],['192.0.0.0',24],['192.168.0.0',16],['198.18.0.0',15],['224.0.0.0',4],['240.0.0.0',4]]
  .forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv4'));
[['::',128],['::1',128],['fc00::',7],['fe80::',10],['ff00::',8]]
  .forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv6'));

function isBlocked(addr) {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (m) addr = m[1];
  return blocked.check(addr, net.isIPv6(addr) ? 'ipv6' : 'ipv4');
}

// Custom lookup used for every outgoing connection (also protects against DNS rebinding).
function safeLookup(host, opts, cb) {
  dns.lookup(host, { all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = addrs.filter(a => !isBlocked(a.address));
    if (!ok.length) return cb(new Error('BLOCKED'));
    if (opts && opts.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}

function parseTarget(input) {
  let s = String(input || '').trim().slice(0, 255);
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  const h = u.hostname.replace(/\.$/, '').toLowerCase();
  if (!h || h === 'localhost' || (!h.includes('.') && !net.isIP(h))) return null;
  return h;
}

/* ---------- Network helpers ---------- */
function head(scheme, host, p) {
  return new Promise((resolve, reject) => {
    const mod = scheme === 'https' ? https : http;
    const req = mod.request({
      host, servername: net.isIP(host) ? undefined : host,
      port: scheme === 'https' ? 443 : 80, path: p, method: 'GET',
      lookup: safeLookup, timeout: TIMEOUT, rejectUnauthorized: false,
      headers: { 'User-Agent': 'Kalkan-SecCheck/1.0', Accept: '*/*' }
    }, res => { resolve({ status: res.statusCode, headers: res.headers }); res.destroy(); });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

async function fetchPage(host) {
  let h = host, p = '/', r = null;
  for (let i = 0; i < 4; i++) {
    try { r = await head('https', h, p); } catch (e) { if (r) break; throw e; }
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      try {
        const u = new URL(loc, `https://${h}${p}`);
        if (u.protocol === 'https:') { h = u.hostname; p = u.pathname + u.search; continue; }
      } catch {}
    }
    break;
  }
  return { ...r, host: h };
}

function tlsInfo(host) {
  return new Promise(resolve => {
    const s = tls.connect({
      host, port: 443, servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false, lookup: safeLookup, timeout: TIMEOUT
    }, () => {
      const c = s.getPeerCertificate();
      resolve({
        ok: true, authorized: s.authorized, authError: s.authorizationError || null,
        protocol: s.getProtocol(), validTo: c && c.valid_to ? new Date(c.valid_to) : null
      });
      s.end();
    });
    s.on('error', () => resolve({ ok: false }));
    s.on('timeout', () => { s.destroy(); resolve({ ok: false }); });
  });
}

async function httpRedirect(host) {
  try {
    const r = await head('http', host, '/');
    const loc = String(r.headers.location || '');
    return r.status >= 300 && r.status < 400 && /^https:/i.test(loc) ? 'pass' : 'fail';
  } catch { return 'closed'; } // port 80 closed: nothing to downgrade to
}

async function secTxt(host) {
  try {
    const r = await head('https', host, '/.well-known/security.txt');
    return r.status === 200 && /text\/plain/i.test(r.headers['content-type'] || '');
  } catch { return false; }
}

const parents = h => {
  const p = h.split('.'), out = [];
  for (let i = 0; i <= p.length - 2; i++) out.push(p.slice(i).join('.'));
  return out;
};
async function txt(name) {
  try { return (await dns.promises.resolveTxt(name)).map(a => a.join('')); } catch { return []; }
}
async function dnsChecks(host) {
  if (net.isIP(host)) return {};
  let spf = null, dmarc = null, caa = false;
  for (const n of parents(host)) {
    if (!spf) spf = (await txt(n)).find(t => /^v=spf1/i.test(t)) || null;
    if (!dmarc) dmarc = (await txt('_dmarc.' + n)).find(t => /^v=DMARC1/i.test(t)) || null;
    if (!caa) { try { caa = (await dns.promises.resolveCaa(n)).length > 0; } catch {} }
  }
  return { spf, dmarc, caa };
}

/* ---------- Scan + scoring (weights sum to 100) ---------- */
async function scan(host) {
  const page = await fetchPage(host).catch(() => null);
  const h = page ? page.host : host;
  const [T, redir, hasTxt, D] = await Promise.all([tlsInfo(h), httpRedirect(host), secTxt(h), dnsChecks(host)]);

  const hd = page ? page.headers : {};
  const P = !!page;
  const checks = [];
  const add = (id, max, status, data) => checks.push({
    id, max, status,
    points: status === 'pass' ? max : status === 'warn' ? Math.round(max / 2) : 0,
    data: data == null || data === '' ? null : String(data).slice(0, 80)
  });
  const csp = hd['content-security-policy'] || '';
  const hsts = /max-age=(\d+)/i.exec(hd['strict-transport-security'] || '');
  const cookies = [].concat(hd['set-cookie'] || []);
  const badCookies = cookies.filter(c => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c) || !/;\s*samesite/i.test(c)).length;
  const srv = hd.server || '', xpb = hd['x-powered-by'] || '';
  const leak = !!xpb || /\d+\.\d+/.test(srv);
  const days = T.ok && T.validTo ? Math.floor((T.validTo - Date.now()) / 864e5) : null;
  const ref = hd['referrer-policy'];

  add('tls_valid', 15, T.ok && T.authorized ? 'pass' : 'fail', T.ok && !T.authorized ? T.authError : null);
  add('tls_version', 8, !T.ok ? 'fail' : T.protocol === 'TLSv1.3' ? 'pass' : T.protocol === 'TLSv1.2' ? 'warn' : 'fail', T.ok ? T.protocol : null);
  add('tls_expiry', 5, days == null ? 'fail' : days > 30 ? 'pass' : days >= 7 ? 'warn' : 'fail', days);
  add('https_redirect', 7, redir === 'fail' ? 'fail' : 'pass', redir === 'closed' ? 'port 80 closed' : null);
  add('hsts', 10, P && hsts ? (+hsts[1] >= 15552000 ? 'pass' : 'warn') : 'fail', P ? hd['strict-transport-security'] : null);
  add('csp', 12, P && csp ? (/unsafe-(inline|eval)/i.test(csp) ? 'warn' : 'pass') : 'fail');
  add('xfo', 6, P && (hd['x-frame-options'] || /frame-ancestors/i.test(csp)) ? 'pass' : 'fail');
  add('xcto', 5, P && String(hd['x-content-type-options'] || '').toLowerCase().includes('nosniff') ? 'pass' : 'fail');
  add('referrer', 4, P && ref ? (/unsafe-url/i.test(ref) ? 'warn' : 'pass') : 'fail', P ? ref : null);
  add('permissions', 3, P && (hd['permissions-policy'] || hd['feature-policy']) ? 'pass' : 'fail');
  add('cookies', 8, !P ? 'fail' : !cookies.length || !badCookies ? 'pass' : badCookies < cookies.length ? 'warn' : 'fail',
      cookies.length ? `${cookies.length - badCookies}/${cookies.length}` : null);
  add('server_leak', 4, !P ? 'fail' : leak ? 'warn' : 'pass', leak ? [srv, xpb].filter(Boolean).join(' | ') : null);
  add('spf', 4, D.spf ? (/[-~]all\b/i.test(D.spf) ? 'pass' : 'warn') : 'fail');
  add('dmarc', 5, D.dmarc ? (/p=(reject|quarantine)/i.test(D.dmarc) ? 'pass' : 'warn') : 'fail', D.dmarc);
  add('caa', 2, D.caa ? 'pass' : 'fail');
  add('security_txt', 2, hasTxt ? 'pass' : 'fail');

  const score = checks.reduce((s, c) => s + c.points, 0);
  const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
  return { host, finalHost: h, score, grade, checks };
}

/* ---------- Rate limit: 10 scans / minute / IP ---------- */
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const a = (hits.get(ip) || []).filter(t => now - t < 60000);
  a.push(now); hits.set(ip, a);
  return a.length > 10;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, a] of hits) if (!a.length || now - a[a.length - 1] > 60000) hits.delete(k);
}, 60000).unref();

/* ---------- HTTP server ---------- */
const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8']
};

http.createServer(async (req, res) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  const u = new URL(req.url, 'http://localhost');

  if (u.pathname === '/api/scan') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    const send = (code, o) => { res.statusCode = code; res.end(JSON.stringify(o)); };
    // Behind a reverse proxy, use the forwarded address instead of the socket address.
    const ip = req.socket.remoteAddress;
    if (limited(ip)) return send(429, { error: 'rate' });
    const host = parseTarget(u.searchParams.get('url'));
    if (!host) return send(400, { error: 'invalid' });
    let addrs;
    try { addrs = await dns.promises.lookup(host, { all: true }); } catch { return send(200, { error: 'unreachable' }); }
    if (addrs.every(a => isBlocked(a.address))) return send(200, { error: 'blocked' });
    try { return send(200, await scan(host)); } catch { return send(500, { error: 'generic' }); }
  }

  const f = FILES[u.pathname];
  if (!f) { res.statusCode = 404; return res.end('Not found'); }
  fs.readFile(path.join(PUB, f[0]), (err, data) => {
    if (err) { res.statusCode = 500; return res.end('Error'); }
    res.setHeader('Content-Type', f[1]);
    res.end(data);
  });
}).listen(PORT, () => console.log(`Қалқан: http://localhost:${PORT}`));
