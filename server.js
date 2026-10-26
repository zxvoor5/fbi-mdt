#!/usr/bin/env node
'use strict';
/*
  خادم «مركز العمليات الميدانية»
  - بدون أي مكتبات خارجية، يتطلب Node.js 18 أو أحدث
  - التشغيل:  node server.js
  - التفاصيل: README.md
*/
const http = require('http'), https = require('https'), fs = require('fs'), path = require('path'),
  crypto = require('crypto'), zlib = require('zlib'), { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

/* ───────── الإعدادات (متغيرات بيئة اختيارية) ───────── */
const env = process.env;
const PORT = +env.PORT || 3000, HOST = env.HOST || '0.0.0.0';
const FILE = path.resolve(env.DATA_FILE || path.join(__dirname, 'data', 'db.json'));
const PAGE = path.join(__dirname, 'index.html');
const MAX_BODY = (+env.MAX_BODY_MB || 30) * 1048576;
const TRUST_PROXY = env.TRUST_PROXY === '1';
const TZ = env.DISPLAY_TZ || 'Asia/Riyadh';
const IDLE = 12 * 36e5, LIFE = 7 * 864e5, WIN = 15 * 6e4, COOKIE = 'fh_sid';

/* ───────── ثوابت النظام (يجب أن تطابق الواجهة) ───────── */
const PERMS = ['roster', 'schedule', 'ranks', 'suspects', 'evidence', 'vehicles', 'legal', 'operations', 'circulars', 'classified', 'vault', 'board', 'radar', 'comms', 'sector'];
const RECS = ['suspects', 'evidence', 'vehicles', 'legal', 'operations', 'circulars', 'classified', 'vault'];
const DAYS = ['السبت', 'الأحد', 'الاثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة'];
const ST = ['حاضر', 'غائب', 'متأخر', 'في إجازة'];
const CHANNELS = ['المكتب', 'الشرطة', 'الدوريات', 'الإسعاف', 'العدل'];
const DEF_RANKS = [['Director', 'المدير', 10, '#d4162c'], ['Deputy Director', 'نائب المدير', 9, '#e0a82e'], ['Special Agent in Charge', 'العميل الخاص المسؤول', 7, '#3b82f6'], ['Senior Special Agent', 'عميل خاص أول', 5, '#22a45d'], ['Special Agent', 'عميل خاص', 3, '#9aa0ae'], ['Cadet', 'متدرب', 1, '#6b7280']].map(r => ({ en: r[0], ar: r[1], l: r[2], c: r[3] }));

/* ───────── التحقق من البيانات القادمة من المتصفح ─────────
   الواجهة تدرج بعض الحقول في HTML بدون ترميز (الشارة، الأوقات، الألوان، الشعار…)،
   لذلك يرفض الخادم أي قيمة لا تطابق الشكل المتوقع حتى لا تُخزَّن شيفرة ضارة. */
class Http extends Error { constructor(s, m) { super(m); this.s = s } }
const bad = m => { throw new Http(400, m) };
const S = (max = 500) => v => { if (v == null) return ''; if (typeof v !== 'string' && typeof v !== 'number') bad('نص غير صالح'); v = String(v); if (v.length > max) bad('النص أطول من المسموح'); return v };
const N = (lo, hi) => v => { if (v === '' || v == null || typeof v === 'boolean') bad('رقم غير صالح'); v = Number(v); if (!Number.isFinite(v) || v < lo || v > hi) bad('رقم خارج النطاق'); return v };
const E = (...o) => v => { if (!o.includes(v)) bad('قيمة غير مسموحة'); return v };
const RE = (re, max = 1000) => v => { if (typeof v !== 'string' || v.length > max || !re.test(v)) bad('صيغة غير صالحة'); return v };
const OBJ = sh => v => { if (!v || typeof v !== 'object' || Array.isArray(v)) bad('عنصر غير صالح'); const o = {}; for (const k in sh) o[k] = sh[k](v[k]); return o };
const ARR = (it, max) => v => { if (v == null) return []; if (!Array.isArray(v) || v.length > max) bad('قائمة غير صالحة أو كبيرة جداً'); return v.map(x => it(x)) };

const IMG = RE(/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/=]+$/, 1.5e6);
const LOGO = RE(/^(data:image\/(png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+\/=]+)?$/, 3e6);
const ID = RE(/^[A-Za-z0-9]{1,16}$/, 16);
const B64 = RE(/^[A-Za-z0-9+\/=]{1,64}$/, 64);
const REC = OBJ({ t: S(300), d: S(5000), tag: E('سري', 'داخلي', 'عام'), st: E('مفتوح', 'نشط', 'مغلق') });
const SCHEMA = Object.assign(Object.create(null), {
  org: v => S(100)(v).trim() || 'مركز العمليات الميدانية',
  threat: v => Math.round(N(0, 4)(v)),
  note: S(2000), logo: LOGO, map: LOGO,
  people: ARR(OBJ({ n: S(100), b: N(0, 1e9), r: S(80), s: E(...ST), o: S(1000) }), 5000),
  sched: ARR(OBJ({ d: E(...DAYS), f: RE(/^(\d{2}:\d{2})?$/, 5), e: RE(/^(\d{2}:\d{2})?$/, 5), x: S(200), a: S(100) }), 5000),
  ranks: ARR(OBJ({ en: S(60), ar: S(60), l: N(0, 100), c: RE(/^#[0-9a-fA-F]{6}$/, 7) }), 100),
  pins: ARR(OBJ({ n: S(100), x: N(0, 100), y: N(0, 100) }), 2000),
  board: OBJ({
    nodes: ARR(OBJ({ id: ID, t: E('شخص', 'دليل', 'موقع', 'مركبة', 'حدث'), n: S(200), o: S(2000), x: N(-5000, 6000), y: N(-5000, 6000) }), 1000),
    links: ARR(OBJ({ a: ID, b: ID, l: S(100) }), 5000)
  })
});
for (const k of RECS) SCHEMA['rec.' + k] = ARR(REC, 5000);
SCHEMA['rec.vehicles'] = ARR(OBJ({ pl: S(40), m: S(100), o: S(2000), imgs: ARR(IMG, 4) }), 2000);
/* الخزنة: الخادم لا يرى إلا نصاً مشفّراً في المتصفح (عنصر واحد) */
SCHEMA['rec.vault'] = ARR(OBJ({ s: B64, i: B64, c: RE(/^[A-Za-z0-9+\/=]+$/, 4e6) }), 1);

/* من يقرأ وماذا (null = للمسؤول الكامل فقط) */
const READ = { people: ['roster'], sched: ['schedule'], ranks: ['ranks', 'roster'], pins: ['radar'], board: ['board'] };
const WRITE = { org: null, logo: null, map: null, threat: 'sector', note: 'sector', people: 'roster', sched: 'schedule', ranks: 'ranks', pins: 'radar', board: 'board' };
for (const k of RECS) WRITE['rec.' + k] = k;

/* ───────── قاعدة البيانات (ملف JSON بكتابة آمنة + نسخة احتياطية يومية) ───────── */
const fresh = () => ({
  users: [], sessions: {}, audit: [], msgs: [],
  state: { org: 'مركز العمليات الميدانية', threat: 2, note: 'القطاع يعمل. مراقبة النشاط في المناطق الثلاث مستمرة.', logo: '', map: '', people: [], sched: [], ranks: DEF_RANKS, pins: [], board: { nodes: [], links: [] }, rec: {} }
});
let db;
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')) }
catch (e) {
  if (e.code !== 'ENOENT') { console.error('تعذّرت قراءة ملف البيانات (لن يُستبدل):', FILE, '\n', e.message); process.exit(1) }
  db = fresh();
}
{ const f = fresh(); for (const k in f) if (!(k in db)) db[k] = f[k]; for (const k in f.state) if (!(k in db.state)) db.state[k] = f.state[k]; for (const k of RECS) if (!Array.isArray(db.state.rec[k])) db.state.rec[k] = [] }

let timer = null;
function save() { if (!timer) timer = setTimeout(flush, 300) }
function flush() {
  if (timer) clearTimeout(timer); timer = null;
  try {
    const dir = path.dirname(FILE), bdir = path.join(dir, 'backups'), bk = path.join(bdir, 'db-' + new Date().toISOString().slice(0, 10) + '.json');
    fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(FILE) && !fs.existsSync(bk)) {
      fs.mkdirSync(bdir, { recursive: true }); fs.copyFileSync(FILE, bk);
      fs.readdirSync(bdir).filter(f => /^db-.*\.json$/.test(f)).sort().slice(0, -14).forEach(f => fs.unlinkSync(path.join(bdir, f)));
    }
    const tmp = FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 }); fs.renameSync(tmp, FILE);
  } catch (e) { console.error('فشل حفظ البيانات:', e.message) }
}

/* ───────── كلمات المرور والجلسات ───────── */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
async function hash(p) { const s = crypto.randomBytes(16), d = await scrypt(p, s, 64); return s.toString('hex') + ':' + d.toString('hex') }
async function verify(p, stored) { const [s, h] = stored.split(':'); return crypto.timingSafeEqual(await scrypt(p, Buffer.from(s, 'hex'), 64), Buffer.from(h, 'hex')) }
const DUMMY = '00'.repeat(16) + ':' + '00'.repeat(64);   /* لتساوي زمن الرد إن لم يوجد المستخدم */
const findUser = n => { const k = String(n).toLowerCase(); return db.users.find(x => x.u.toLowerCase() === k) };
const checkPw = p => { if (typeof p !== 'string' || p.length < 8 || p.length > 200) throw new Http(400, 'كلمة المرور يجب ألا تقل عن 8 أحرف') };
const cleanPerms = a => [...new Set((Array.isArray(a) ? a : []).filter(p => PERMS.includes(p)))];
const dropSessions = (u, keep) => { const k = u.u.toLowerCase(); for (const id in db.sessions) if (db.sessions[id].u === k && id !== keep) delete db.sessions[id] };

function auth(req) {
  const t = (/(?:^|;\s*)fh_sid=([\w-]+)/.exec(req.headers.cookie || '') || [])[1]; if (!t) return null;
  const id = sha(t), s = db.sessions[id], n = Date.now(); if (!s) return null;
  if (n > s.exp || n > s.t0 + LIFE) { delete db.sessions[id]; return null }
  const u = db.users.find(x => x.u.toLowerCase() === s.u); if (!u) { delete db.sessions[id]; return null }
  s.exp = n + IDLE; req.sid = id; return u;
}
const need = req => { const u = auth(req); if (!u) throw new Http(401, 'يلزم تسجيل الدخول'); return u };
const admin = u => { if (!u.full) throw new Http(403, 'للمسؤول فقط') };
const has = (u, p) => !!u.full || u.perms.includes(p);
const pub = u => ({ u: u.u, full: u.full ? 1 : 0, perms: u.perms });
function allowed(u, k) { const p = WRITE[k]; return p === null ? !!u.full : has(u, p) }

/* حماية من تخمين كلمات المرور */
const fails = new Map();
const locked = (k, max) => { const f = fails.get(k); return f && f.c >= max && Date.now() < f.until ? Math.ceil((f.until - Date.now()) / 6e4) : 0 };
const miss = (k, max) => { const n = Date.now(); let f = fails.get(k); if (!f || n - f.t > WIN) fails.set(k, f = { c: 0, t: n, until: 0 }); if (++f.c >= max) f.until = n + WIN };
setInterval(() => {
  const n = Date.now(); for (const [k, f] of fails) if (n - f.t > WIN) fails.delete(k);
  let ch = 0; for (const k in db.sessions) { const s = db.sessions[k]; if (n > s.exp || n > s.t0 + LIFE) { delete db.sessions[k]; ch = 1 } } if (ch) save();
}, 6e5).unref();

function audit(u, e, ip) { db.audit.push({ t: Date.now(), u, e, ip }); if (db.audit.length > 5000) db.audit.splice(0, db.audit.length - 5000) }

/* ───────── أدوات HTTP ───────── */
const secure = req => !!req.socket.encrypted || (TRUST_PROXY && /^https/i.test(req.headers['x-forwarded-proto'] || ''));
const clientIp = req => TRUST_PROXY && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',').pop().trim() : req.socket.remoteAddress;
function sameOrigin(req) {
  const o = req.headers.origin; if (!o) return true;
  try { return new URL(o).host === ((TRUST_PROXY && String(req.headers['x-forwarded-host'] || '').split(',')[0].trim()) || req.headers.host) } catch { return false }
}
function secHeaders(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  if (secure(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}
function out(req, res, code, type, b, extra) {
  const h = { 'Content-Type': type, ...extra };
  if (b.length > 1024 && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) { b = zlib.gzipSync(b); h['Content-Encoding'] = 'gzip'; h.Vary = 'Accept-Encoding' }
  h['Content-Length'] = b.length; res.writeHead(code, h); res.end(b);
}
const send = (req, res, code, o) => out(req, res, code, 'application/json; charset=utf-8', Buffer.from(JSON.stringify(o)));
function readJson(req) {
  return new Promise((ok, no) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > MAX_BODY) { no(new Http(413, 'حجم البيانات كبير جداً')); req.destroy(); return } c.push(d) });
    req.on('end', () => { if (!n) return ok({}); try { ok(JSON.parse(Buffer.concat(c).toString('utf8'))) } catch { no(new Http(400, 'JSON غير صالح')) } });
    req.on('error', no);
  });
}

/* ───────── المسارات ───────── */
const recent = () => db.msgs.slice(-300).map(({ u, c, x, t }) => ({ u, c, x, t }));
function stateFor(u) {
  const s = db.state, o = { org: s.org, threat: s.threat, note: s.note, logo: s.logo, map: s.map, rec: {} };
  for (const k in READ) if (READ[k].some(p => has(u, p))) o[k] = s[k];
  for (const k of RECS) if (has(u, k)) o.rec[k] = s.rec[k];
  return o;
}
function putState(req, res, u, b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw new Http(400, 'طلب غير صالح');
  const ok = {}, rej = [];
  for (const k of Object.keys(b)) {
    if (!Object.hasOwn(SCHEMA, k) || !allowed(u, k)) { rej.push(k); continue }
    try { ok[k] = SCHEMA[k](b[k]) } catch (e) { if (e instanceof Http) throw new Http(400, `بيانات غير صالحة (${k}): ${e.message}`); throw e }
  }
  const ip = clientIp(req);
  for (const k in ok) { if (k.startsWith('rec.')) db.state.rec[k.slice(4)] = ok[k]; else db.state[k] = ok[k]; audit(u.u, 'edit:' + k, ip) }
  if (Object.keys(ok).length) save();
  send(req, res, 200, { ok: true, rejected: rej });
}
async function login(req, res, b) {
  const name = String(b.u ?? '').trim().slice(0, 60), pw = String(b.p ?? '').slice(0, 200), ip = clientIp(req), k = name.toLowerCase();
  const wait = Math.max(locked('ip:' + ip, 8), locked('u:' + k, 12));
  if (wait) throw new Http(429, `محاولات كثيرة. حاول بعد ${wait} دقيقة`);
  const u = db.users.find(x => x.u.toLowerCase() === k), ok = await verify(pw, u ? u.pw : DUMMY);
  if (!u || !ok) { miss('ip:' + ip, 8); miss('u:' + k, 12); audit(name.slice(0, 40) || '—', 'fail', ip); save(); throw new Http(401, 'اسم المستخدم أو كلمة المرور غير صحيحة') }
  fails.delete('ip:' + ip); fails.delete('u:' + k);
  const t = crypto.randomBytes(32).toString('base64url'), n = Date.now();
  db.sessions[sha(t)] = { u: k, exp: n + IDLE, t0: n };
  audit(u.u, 'login', ip); save();
  res.setHeader('Set-Cookie', `${COOKIE}=${t}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${LIFE / 1000}${secure(req) || env.COOKIE_SECURE === '1' ? '; Secure' : ''}`);
  send(req, res, 200, pub(u));
}
function logout(req, res) {
  const u = auth(req); if (u) { delete db.sessions[req.sid]; audit(u.u, 'logout', clientIp(req)); save() }
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
  send(req, res, 200, { ok: true });
}
function postMsg(req, res, u, b) {
  const c = String(b.c ?? ''), x = String(b.x ?? '').trim();
  if (!CHANNELS.includes(c)) throw new Http(400, 'قناة غير صالحة');
  if (!x || x.length > 2000) throw new Http(400, 'الرسالة فارغة أو طويلة جداً');
  db.msgs.push({ u: u.u, c, x, t: new Date().toLocaleTimeString('ar', { hour: '2-digit', minute: '2-digit', timeZone: TZ }), ts: Date.now() });
  if (db.msgs.length > 1000) db.msgs.splice(0, db.msgs.length - 1000);
  save(); send(req, res, 200, { ok: true });
}
async function addUser(req, res, a, b) {
  const name = String(b.u ?? '').trim();
  if (!/^[^\x00-\x1f<>"'&]{2,40}$/.test(name)) throw new Http(400, 'اسم المستخدم غير صالح (من 2 إلى 40 حرفاً بدون رموز خاصة)');
  checkPw(b.p);
  if (findUser(name)) throw new Http(409, 'اسم المستخدم مستخدم مسبقاً');
  db.users.push({ u: name, pw: await hash(b.p), full: b.full ? 1 : 0, perms: cleanPerms(b.perms) });
  audit(a.u, 'إنشاء حساب: ' + name, clientIp(req)); save(); send(req, res, 200, { ok: true });
}
async function patchUser(req, res, a, name, b) {
  const t = findUser(name); if (!t) throw new Http(404, 'المستخدم غير موجود');
  const self = t === a, what = [];
  if ('full' in b) { const f = b.full ? 1 : 0; if (self && !f) throw new Http(400, 'لا يمكنك إزالة صلاحية المسؤول من حسابك'); t.full = f; what.push('صلاحية المسؤول') }
  if (Array.isArray(b.perms)) { t.perms = cleanPerms(b.perms); what.push('الصلاحيات') }
  if (typeof b.p === 'string' && b.p !== '') { checkPw(b.p); t.pw = await hash(b.p); dropSessions(t, self ? req.sid : null); what.push('كلمة المرور') }
  if (what.length) audit(a.u, `تعديل حساب ${t.u}: ${what.join('، ')}`, clientIp(req));
  save(); send(req, res, 200, { ok: true });
}
function delUser(req, res, a, name) {
  const t = findUser(name); if (!t) throw new Http(404, 'المستخدم غير موجود');
  if (t === a) throw new Http(400, 'لا يمكنك حذف حسابك الحالي');
  dropSessions(t, null); db.users.splice(db.users.indexOf(t), 1);
  audit(a.u, 'حذف حساب: ' + t.u, clientIp(req)); save(); send(req, res, 200, { ok: true });
}
function page(req, res) {
  let b; try { b = fs.readFileSync(PAGE) } catch { throw new Http(500, 'ملف index.html غير موجود بجانب server.js') }
  out(req, res, 200, 'text/html; charset=utf-8', b, { 'Cache-Control': 'no-cache' });
}

async function handle(req, res) {
  const p = new URL(req.url, 'http://x').pathname, m = req.method;
  secHeaders(req, res);
  if (m === 'GET' && (p === '/' || p === '/index.html')) return page(req, res);
  if (p === '/favicon.ico') { res.writeHead(204); return res.end() }
  if (!p.startsWith('/api/')) throw new Http(404, 'غير موجود');
  res.setHeader('Cache-Control', 'no-store');
  if (m !== 'GET' && !sameOrigin(req)) throw new Http(403, 'مصدر الطلب غير مسموح');
  let b = {};
  if (m === 'POST' || m === 'PUT' || m === 'PATCH') {
    if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw new Http(415, 'نوع المحتوى غير مدعوم');
    if ((+req.headers['content-length'] || 0) > MAX_BODY) throw new Http(413, 'حجم البيانات كبير جداً');
    b = await readJson(req);
  }
  if (m === 'GET' && p === '/api/health') return send(req, res, 200, { ok: true });
  if (m === 'GET' && p === '/api/public') return send(req, res, 200, { org: db.state.org, logo: db.state.logo });
  if (m === 'POST' && p === '/api/login') return login(req, res, b);
  if (m === 'POST' && p === '/api/logout') return logout(req, res);

  const u = need(req);   /* كل ما بعده يتطلب تسجيل دخول */
  if (m === 'GET' && p === '/api/me') return send(req, res, 200, pub(u));
  if (m === 'GET' && p === '/api/state') return send(req, res, 200, { state: stateFor(u), msgs: has(u, 'comms') ? recent() : [] });
  if (m === 'PUT' && p === '/api/state') return putState(req, res, u, b);
  if (p === '/api/msgs') {
    if (!has(u, 'comms')) throw new Http(403, 'لا تملك صلاحية');
    if (m === 'GET') return send(req, res, 200, recent());
    if (m === 'POST') return postMsg(req, res, u, b);
  }
  if (m === 'GET' && p === '/api/audit') { admin(u); return send(req, res, 200, db.audit.slice(-500).reverse()) }
  if (p === '/api/users') {
    admin(u);
    if (m === 'GET') return send(req, res, 200, db.users.map(pub));
    if (m === 'POST') return addUser(req, res, u, b);
  }
  const mt = /^\/api\/users\/([^/]+)$/.exec(p);
  if (mt) {
    admin(u); let n; try { n = decodeURIComponent(mt[1]) } catch { throw new Http(400, 'اسم غير صالح') }
    if (m === 'PATCH') return patchUser(req, res, u, n, b);
    if (m === 'DELETE') return delUser(req, res, u, n);
  }
  throw new Http(404, 'غير موجود');
}
const onReq = (req, res) => handle(req, res).catch(e => {
  if (res.headersSent) return res.destroy();
  if (e instanceof Http) return send(req, res, e.s, { error: e.message });
  console.error(e); send(req, res, 500, { error: 'خطأ في الخادم' });
});

/* ───────── التشغيل ───────── */
(async () => {
  /* node server.js passwd <المستخدم> [كلمة المرور]  ← لاستعادة الدخول (أوقف الخادم أولاً) */
  if (process.argv[2] === 'passwd') {
    const u = findUser(process.argv[3] || ''), pw = process.argv[4] || crypto.randomBytes(9).toString('base64url');
    if (!u) { console.error('المستخدم غير موجود.\nالاستخدام: node server.js passwd <اسم المستخدم> [كلمة المرور]'); process.exit(1) }
    if (pw.length < 8) { console.error('كلمة المرور يجب ألا تقل عن 8 أحرف'); process.exit(1) }
    u.pw = await hash(pw); dropSessions(u, null); flush();
    console.log(`تم تعيين كلمة مرور جديدة للمستخدم «${u.u}»:  ${pw}`); return;
  }
  if (!db.users.length) {
    const name = env.ADMIN_USER || 'admin', pw = env.ADMIN_PASS || crypto.randomBytes(9).toString('base64url');
    if (pw.length < 8) { console.error('ADMIN_PASS يجب ألا تقل عن 8 أحرف'); process.exit(1) }
    db.users.push({ u: name, pw: await hash(pw), full: 1, perms: [] }); flush();
    console.log('\n┌──────────────────────────────────────────────┐\n│  تم إنشاء حساب المسؤول الأول (يظهر مرة واحدة)  │\n└──────────────────────────────────────────────┘');
    console.log(`  المستخدم:     ${name}\n  كلمة المرور:  ${env.ADMIN_PASS ? '(المأخوذة من ADMIN_PASS)' : pw}\n  غيّرها من صفحة «الإدارة» بعد أول دخول.\n`);
  }
  const srv = env.TLS_CERT && env.TLS_KEY
    ? https.createServer({ cert: fs.readFileSync(env.TLS_CERT), key: fs.readFileSync(env.TLS_KEY) }, onReq)
    : http.createServer(onReq);
  srv.listen(PORT, HOST, () => console.log(`الخادم يعمل:  ${srv instanceof https.Server ? 'https' : 'http'}://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}\nملف البيانات: ${FILE}`));
  for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { flush(); process.exit(0) });
})();
