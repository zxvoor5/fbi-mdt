'use strict';
const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');
const TTL = 12 * 3600 * 1000; // مدة الجلسة: 12 ساعة
const REC_KEYS = ['suspects', 'evidence', 'legal', 'operations', 'circulars', 'classified', 'vehicles', 'vault'];
const ALL_PERMS = ['roster', 'schedule', 'ranks', ...REC_KEYS, 'radar', 'board', 'comms', 'sector'];
const SEC = { people: 'roster', sched: 'schedule', ranks: 'ranks', pins: 'radar' };

/* ---------- كلمات المرور والتوكن ---------- */
const hash = (p, salt) => crypto.scryptSync(p, salt, 64).toString('hex');
function mkUser(u, p, full, perms) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { u, salt, hash: hash(p, salt), full: full ? 1 : 0, perms: (perms || []).filter(x => ALL_PERMS.includes(x)) };
}
function check(user, p) {
  const a = Buffer.from(hash(p, user.salt), 'hex'), b = Buffer.from(user.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ---------- التخزين ---------- */
function defaultState() {
  return {
    org: 'مركز العمليات الميدانية', threat: 2, note: 'القطاع يعمل. مراقبة النشاط في المناطق الثلاث مستمرة.', logo: '', map: '',
    people: [], sched: [], pins: [], board: { nodes: [], links: [] },
    ranks: [['Director', 'المدير', 10, '#d4162c'], ['Deputy Director', 'نائب المدير', 9, '#e0a82e'], ['Special Agent in Charge', 'العميل الخاص المسؤول', 7, '#3b82f6'],
      ['Senior Special Agent', 'عميل خاص أول', 5, '#22a45d'], ['Special Agent', 'عميل خاص', 3, '#9aa0ae'], ['Cadet', 'متدرب', 1, '#6b7280']].map(r => ({ en: r[0], ar: r[1], l: r[2], c: r[3] })),
    rec: { suspects: [], legal: [], operations: [], classified: [],
      evidence: [{ t: 'فوارغ طلقات - الموقع الأول', d: 'تم العثور على فوارغ رصاص في مكان الحادث.', tag: 'سري', st: 'مفتوح' }],
      circulars: [{ t: 'التوجيه 01-2026', d: 'يجب على جميع الموظفين تسجيل الحضور في بداية نوبتهم.', tag: 'داخلي', st: 'نشط' }] }
  };
}
let db = null;
try { db = JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch {}
function persist() {
  fs.mkdirSync(path.dirname(DATA), { recursive: true });
  const t = DATA + '.tmp';
  fs.writeFileSync(t, JSON.stringify(db));
  fs.renameSync(t, DATA);
}
if (!db) {
  db = { secret: crypto.randomBytes(32).toString('hex'), users: [], msgs: [], state: defaultState() };
  const pass = process.env.ADMIN_PASS || crypto.randomBytes(9).toString('base64url');
  db.users.push(mkUser('admin', pass, 1, []));
  persist();
  console.log('\n=== أول تشغيل ===\nالمستخدم: admin\nكلمة المرور: ' + pass + '\nغيّرها فور الدخول من صفحة الإدارة.\n');
}

db.state.board = db.state.board || { nodes: [], links: [] };
db.audit = db.audit || [];
REC_KEYS.forEach(k => { db.state.rec[k] = db.state.rec[k] || []; });
const sign = s => crypto.createHmac('sha256', db.secret).update(s).digest('base64url');
const mkToken = u => { const b = Buffer.from(JSON.stringify({ u, exp: Date.now() + TTL })).toString('base64url'); return b + '.' + sign(b); };
function readToken(t) {
  if (!t) return null;
  const [b, s] = t.split('.');
  if (!b || !s) return null;
  const e = sign(b);
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
  try { const p = JSON.parse(Buffer.from(b, 'base64url')); return p.exp > Date.now() ? p.u : null; } catch { return null; }
}
const cookie = (req, n) => ((req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(n + '=')) || '').slice(n.length + 1);
const pub = u => ({ u: u.u, full: u.full, perms: u.perms });
const log = (u, e) => { db.audit.push({ t: Date.now(), u, e }); if (db.audit.length > 300) db.audit = db.audit.slice(-300); persist(); };

/* ---------- تحديد محاولات الدخول ---------- */
const tries = new Map();
const limited = ip => { const t = tries.get(ip); return t && t.n >= 8 && Date.now() - t.t < 600000; };
const fail = ip => { const t = tries.get(ip); tries.set(ip, t && Date.now() - t.t < 600000 ? { n: t.n + 1, t: t.t } : { n: 1, t: Date.now() }); };

/* ---------- التطبيق ---------- */
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '25mb' }));
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (req.method !== 'GET' && req.headers.origin) {
    try { if (new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ error: 'forbidden' }); }
    catch { return res.status(403).json({ error: 'forbidden' }); }
  }
  next();
});

const auth = (req, res, next) => {
  const u = db.users.find(x => x.u === readToken(cookie(req, 'fh')));
  if (!u) return res.status(401).json({ error: 'سجّل الدخول أولاً' });
  req.user = u; next();
};
const adminOnly = (req, res, next) => req.user.full ? next() : res.status(403).json({ error: 'للمسؤولين فقط' });
const has = (u, p) => u.full || u.perms.includes(p);

app.get('/api/public', (req, res) => res.json({ org: db.state.org, logo: db.state.logo }));

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (limited(ip)) return res.status(429).json({ error: 'محاولات كثيرة، حاول بعد قليل' });
  const { u, p } = req.body || {};
  const user = typeof u === 'string' && db.users.find(x => x.u === u);
  const ok = user ? check(user, String(p ?? '')) : (hash('x', '00'), false);
  if (!ok) { fail(ip); log(typeof u === 'string' ? u.slice(0, 32) : '?', 'fail'); return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' }); }
  tries.delete(ip); log(user.u, 'login');
  res.setHeader('Set-Cookie', `fh=${mkToken(user.u)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${TTL / 1000}${req.secure ? '; Secure' : ''}`);
  res.json(pub(user));
});
app.post('/api/logout', (req, res) => { const lu = readToken(cookie(req, 'fh')); if (lu) log(lu, 'logout'); res.setHeader('Set-Cookie', 'fh=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));

/* ---------- البيانات ---------- */
app.get('/api/state', auth, (req, res) => {
  const u = req.user, st = db.state;
  const out = { org: st.org, threat: st.threat, note: st.note, logo: st.logo, map: st.map, rec: {} };
  if (has(u, 'roster')) out.people = st.people;
  if (has(u, 'schedule')) out.sched = st.sched;
  if (has(u, 'ranks') || has(u, 'roster')) out.ranks = st.ranks;
  if (has(u, 'radar')) out.pins = st.pins;
  if (has(u, 'board')) out.board = st.board;
  REC_KEYS.forEach(k => { if (has(u, k)) out.rec[k] = st.rec[k]; });
  res.json({ state: out, msgs: has(u, 'comms') ? db.msgs.slice(-200) : [] });
});

const S_ = (v, n) => String(v ?? '').slice(0, n);
const N = v => Number.isFinite(+v) ? +v : 0;
const arr = a => a.filter(x => x && typeof x === 'object');
const san = {
  people: a => arr(a).map(p => ({ n: S_(p.n, 100), b: N(p.b), r: S_(p.r, 100), s: S_(p.s, 20), o: S_(p.o, 300) })),
  sched: a => arr(a).map(e => ({ d: S_(e.d, 20), f: /^\d{2}:\d{2}$/.test(e.f) ? e.f : '', e: /^\d{2}:\d{2}$/.test(e.e) ? e.e : '', x: S_(e.x, 200), a: S_(e.a, 100) })),
  ranks: a => arr(a).map(r => ({ en: S_(r.en, 100), ar: S_(r.ar, 100), l: N(r.l), c: /^#[0-9a-f]{6}$/i.test(r.c) ? r.c : '#888888' })),
  pins: a => arr(a).map(p => ({ n: S_(p.n, 100), x: N(p.x), y: N(p.y) })),
  board: b => ({
    nodes: arr(b.nodes || []).slice(0, 300).map(n => ({ id: S_(n.id, 20).replace(/\W/g, ''), t: S_(n.t, 20), n: S_(n.n, 100), o: S_(n.o, 300), x: N(n.x), y: N(n.y) })),
    links: arr(b.links || []).slice(0, 600).map(l => ({ a: S_(l.a, 20), b: S_(l.b, 20), l: S_(l.l, 60) }))
  }),
  rec: a => arr(a).map(r => ({ t: S_(r.t, 200), d: S_(r.d, 2000), tag: S_(r.tag, 30), st: S_(r.st, 30) })),
  /* المركبات: رقم اللوحة + حتى 4 صور (data URL) */
  vehicles: a => arr(a).map(v => ({ pl: S_(v.pl, 40), m: S_(v.m, 100), o: S_(v.o, 2000), imgs: (Array.isArray(v.imgs) ? v.imgs : []).filter(s => typeof s === 'string' && s.length < 1.5e6 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(s)).slice(0, 4) })),
  /* الخزنة: نص مشفّر في المتصفح فقط (عنصر واحد). أي قيمة غير base64 يُرفض الطلب كله بدل أن تتلف الخزنة */
  vault: a => arr(a).slice(0, 1).map(v => { const b = (x, n) => { x = String(x ?? ''); if (!x || x.length > n || !/^[A-Za-z0-9+/=]+$/.test(x)) throw new Error('bad vault'); return x; }; return { s: b(v.s, 64), i: b(v.i, 64), c: b(v.c, 4e6) }; })
};
const imgOk = v => v === '' || (typeof v === 'string' && v.length < 3e6 && /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(v));

app.put('/api/state', auth, (req, res) => {
  const u = req.user, st = db.state, rejected = [];
  for (const [k, v] of Object.entries(req.body || {})) {
    let ok = false;
    if (k === 'threat') { if (has(u, 'sector') && Number.isInteger(v) && v >= 0 && v <= 4) { st.threat = v; ok = true; } }
    else if (k === 'note') { if (has(u, 'sector') && typeof v === 'string') { st.note = v.slice(0, 1000); ok = true; } }
    else if (k === 'org') { if (u.full && typeof v === 'string' && v.trim()) { st.org = v.slice(0, 80); ok = true; } }
    else if (k === 'logo' || k === 'map') { if (u.full && imgOk(v)) { st[k] = v; ok = true; } }
    else if (k === 'board') { if (has(u, 'board') && v && typeof v === 'object' && !Array.isArray(v)) { st.board = san.board(v); ok = true; } }
    else if (k.startsWith('rec.')) {
      const r = k.slice(4);
      if (REC_KEYS.includes(r) && has(u, r) && Array.isArray(v) && v.length <= 2000) { try { st.rec[r] = (san[r] || san.rec)(v); ok = true; } catch {} }
    } else if (Object.hasOwn(SEC, k) && san[k] && Array.isArray(v) && v.length <= 2000 && has(u, SEC[k])) { st[k] = san[k](v); ok = true; }
    if (!ok) rejected.push(k);
  }
  const done = Object.keys(req.body || {}).filter(k => !rejected.includes(k));
  if (done.length) log(u.u, 'edit: ' + done.join(',')); else persist();
  res.json({ ok: true, rejected });
});

/* ---------- الرسائل ---------- */
app.get('/api/msgs', auth, (req, res) => res.json(has(req.user, 'comms') ? db.msgs.slice(-200) : []));
app.post('/api/msgs', auth, (req, res) => {
  if (!has(req.user, 'comms')) return res.status(403).json({ error: 'لا تملك الصلاحية' });
  const x = S_(req.body?.x, 1000).trim();
  if (!x) return res.status(400).json({ error: 'رسالة فارغة' });
  db.msgs.push({ u: req.user.u, c: S_(req.body?.c, 30), x, t: new Date().toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit', timeZone: process.env.TZ_NAME || 'Asia/Riyadh' }) });
  if (db.msgs.length > 500) db.msgs = db.msgs.slice(-500);
  persist();
  res.json({ ok: true });
});

/* ---------- الحسابات (للمسؤول) ---------- */
const NAME_RE = /^[\w.\-\u0600-\u06FF]{2,32}$/;
app.get('/api/users', auth, adminOnly, (req, res) => res.json(db.users.map(pub)));
app.post('/api/users', auth, adminOnly, (req, res) => {
  const { u, p, full, perms } = req.body || {};
  if (typeof u !== 'string' || !NAME_RE.test(u)) return res.status(400).json({ error: 'اسم المستخدم غير صالح (2–32 حرفاً بدون مسافات)' });
  if (typeof p !== 'string' || p.length < 6 || p.length > 200) return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });
  if (db.users.some(x => x.u === u)) return res.status(409).json({ error: 'اسم المستخدم مستخدم مسبقاً' });
  db.users.push(mkUser(u, p, full, Array.isArray(perms) ? perms : []));
  persist(); res.json({ ok: true });
});
app.patch('/api/users/:u', auth, adminOnly, (req, res) => {
  const t = db.users.find(x => x.u === req.params.u);
  if (!t) return res.status(404).json({ error: 'الحساب غير موجود' });
  const { full, perms, p } = req.body || {};
  if (full !== undefined) {
    if (t.u === req.user.u) return res.status(400).json({ error: 'لا يمكنك تغيير صلاحية حسابك' });
    t.full = full ? 1 : 0;
  }
  if (Array.isArray(perms)) t.perms = perms.filter(x => ALL_PERMS.includes(x));
  if (p !== undefined) {
    if (typeof p !== 'string' || p.length < 6 || p.length > 200) return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });
    t.salt = crypto.randomBytes(16).toString('hex'); t.hash = hash(p, t.salt);
  }
  persist(); res.json({ ok: true });
});
app.delete('/api/users/:u', auth, adminOnly, (req, res) => {
  if (req.params.u === req.user.u) return res.status(400).json({ error: 'لا يمكنك حذف حسابك' });
  const i = db.users.findIndex(x => x.u === req.params.u);
  if (i < 0) return res.status(404).json({ error: 'الحساب غير موجود' });
  db.users.splice(i, 1); persist(); res.json({ ok: true });
});

app.get('/api/audit', auth, adminOnly, (req, res) => res.json(db.audit.slice(-40).reverse()));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => err && err.type === 'entity.too.large' ? res.status(413).json({ error: 'حجم البيانات كبير جداً، قلّل عدد الصور' }) : res.status(400).json({ error: 'طلب غير صالح' }));
app.listen(PORT, () => console.log('الخادم يعمل على المنفذ ' + PORT));
