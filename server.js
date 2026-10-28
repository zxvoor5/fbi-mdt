'use strict';
const express = require('express'), crypto = require('crypto'), mongoose = require('mongoose'), path = require('path');

const PORT = +process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const TTL = 12 * 3600 * 1000; // مدة الجلسة: 12 ساعة
const REC_KEYS = ['suspects', 'evidence', 'legal', 'operations', 'circulars', 'classified', 'vehicles', 'vault'];
const ALL_PERMS = ['roster', 'schedule', 'ranks', ...REC_KEYS, 'radar', 'board', 'comms', 'sector'];
const SEC = { people: 'roster', sched: 'schedule', ranks: 'ranks', pins: 'radar' };

// --- تعريف نماذج قاعدة البيانات (MongoDB Schemas) ---
const UserSchema = new mongoose.Schema({
  u: { type: String, unique: true, required: true },
  salt: String,
  hash: String,
  full: { type: Number, default: 0 },
  perms: [String]
});
const UserModel = mongoose.model('User', UserSchema);

const StateSchema = new mongoose.Schema({
  key: { type: String, default: 'main_state', unique: true },
  org: { type: String, default: 'مركز العمليات الميدانية' },
  threat: { type: Number, default: 2 },
  note: { type: String, default: 'القطاع يعمل. مراقبة النشاط في المناطق الثلاث مستمرة.' },
  logo: { type: String, default: '' },
  map: { type: String, default: '' },
  people: { type: Array, default: [] },
  sched: { type: Array, default: [] },
  pins: { type: Array, default: [] },
  board: { type: Object, default: { nodes: [], links: [] } },
  ranks: { type: Array, default: [] },
  rec: { type: Object, default: {} }
});
const StateModel = mongoose.model('State', StateSchema);

const MsgSchema = new mongoose.Schema({
  u: String,
  c: String,
  x: String,
  t: String
});
const MsgModel = mongoose.model('Msg', MsgSchema);

const AuditSchema = new mongoose.Schema({
  t: Number,
  u: String,
  e: String
});
const AuditModel = mongoose.model('Audit', AuditSchema);

const SecretSchema = new mongoose.Schema({
  key: { type: String, default: 'app_secret', unique: true },
  secret: String
});
const SecretModel = mongoose.model('Secret', SecretSchema);


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

/* ---------- الاتصال بقاعدة البيانات وبدء الخادم ---------- */
async function startServer() {
  if (!MONGODB_URI) {
    console.error('خطأ: متغير البيئة MONGODB_URI غير موجود!');
    process.exit(1);
  }

  try {
    await mongoose.connect(MONGODB_URI);
    console.log('تم الاتصال بقاعدة بيانات MongoDB Atlas بنجاح.');
  } catch (err) {
    console.error('فشل الاتصال بقاعدة البيانات:', err);
    process.exit(1);
  }

  // تهيئة البيانات الأساسية إذا كانت قاعدة البيانات فارغة
  let secDoc = await SecretModel.findOne({ key: 'app_secret' });
  let secretKey;
  if (!secDoc) {
    secretKey = crypto.randomBytes(32).toString('hex');
    await SecretModel.create({ key: 'app_secret', secret: secretKey });
  } else {
    secretKey = secDoc.secret;
  }

  let stateDoc = await StateModel.findOne({ key: 'main_state' });
  if (!stateDoc) {
    const defaultRanks = [['Director', 'المدير', 10, '#d4162c'], ['Deputy Director', 'نائب المدير', 9, '#e0a82e'], ['Special Agent in Charge', 'العميل الخاص المسؤول', 7, '#3b82f6'],
      ['Senior Special Agent', 'عميل خاص أول', 5, '#22a45d'], ['Special Agent', 'عميل خاص', 3, '#9aa0ae'], ['Cadet', 'متدرب', 1, '#6b7280']].map(r => ({ en: r[0], ar: r[1], l: r[2], c: r[3] }));
    
    const defaultRec = { suspects: [], legal: [], operations: [], classified: [],
      evidence: [{ t: 'فوارغ طلقات - الموقع الأول', d: 'تم العثور على فوارغ رصاص في مكان الحادث.', tag: 'سري', st: 'مفتوح' }],
      circulars: [{ t: 'التوجيه 01-2026', d: 'يجب على جميع الموظفين تسجيل الحضور في بداية نوبتهم.', tag: 'داخلي', st: 'نشط' }] };
    REC_KEYS.forEach(k => { if (!defaultRec[k]) defaultRec[k] = []; });

    stateDoc = await StateModel.create({
      key: 'main_state',
      ranks: defaultRanks,
      rec: defaultRec
    });
  }

  let adminUser = await UserModel.findOne({ u: 'admin' });
  if (!adminUser) {
    const pass = process.env.ADMIN_PASS || crypto.randomBytes(9).toString('base64url');
    const newAdmin = mkUser('admin', pass, 1, []);
    await UserModel.create(newAdmin);
    console.log('\n=== أول تشغيل ===\nالمستخدم: admin\nكلمة المرور: ' + pass + '\nغيّرها فور الدخول من صفحة الإدارة.\n');
  }

  // إعداد التوكن وتسجيل الأحداث
  const sign = s => crypto.createHmac('sha256', secretKey).update(s).digest('base64url');
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
  
  async function logEvent(u, e) {
    await AuditModel.create({ t: Date.now(), u, e });
    const count = await AuditModel.countDocuments();
    if (count > 300) {
      const oldest = await AuditModel.find().sort({ t: 1 }).limit(count - 300);
      if (oldest.length) {
        await AuditModel.deleteMany({ _id: { $in: oldest.map(x => x._id) } });
      }
    }
  }

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

  const auth = async (req, res, next) => {
    const u = await UserModel.findOne({ u: readToken(cookie(req, 'fh')) });
    if (!u) return res.status(401).json({ error: 'سجّل الدخول أولاً' });
    req.user = u; next();
  };
  const adminOnly = (req, res, next) => req.user.full ? next() : res.status(403).json({ error: 'للمسؤولين فقط' });
  const has = (u, p) => u.full || u.perms.includes(p);

  app.get('/api/public', async (req, res) => {
    const st = await StateModel.findOne({ key: 'main_state' });
    res.json({ org: st.org, logo: st.logo });
  });

  app.post('/api/login', async (req, res) => {
    const ip = req.ip;
    if (limited(ip)) return res.status(429).json({ error: 'محاولات كثيرة، حاول بعد قليل' });
    const { u, p } = req.body || {};
    const user = typeof u === 'string' && await UserModel.findOne({ u });
    const ok = user ? check(user, String(p ?? '')) : (hash('x', '00'), false);
    if (!ok) { fail(ip); await logEvent(typeof u === 'string' ? u.slice(0, 32) : '?', 'fail'); return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' }); }
    tries.delete(ip); await logEvent(user.u, 'login');
    res.setHeader('Set-Cookie', `fh=${mkToken(user.u)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${TTL / 1000}${req.secure ? '; Secure' : ''}`);
    res.json(pub(user));
  });
  
  app.post('/api/logout', async (req, res) => {
    const lu = readToken(cookie(req, 'fh'));
    if (lu) await logEvent(lu, 'logout');
    res.setHeader('Set-Cookie', 'fh=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    res.json({ ok: true });
  });

  app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));

  /* ---------- البيانات ---------- */
  app.get('/api/state', auth, async (req, res) => {
    const u = req.user, st = await StateModel.findOne({ key: 'main_state' });
    const out = { org: st.org, threat: st.threat, note: st.note, logo: st.logo, map: st.map, rec: {} };
    if (has(u, 'roster')) out.people = st.people;
    if (has(u, 'schedule')) out.sched = st.sched;
    if (has(u, 'ranks') || has(u, 'roster')) out.ranks = st.ranks;
    if (has(u, 'radar')) out.pins = st.pins;
    if (has(u, 'board')) out.board = st.board;
    REC_KEYS.forEach(k => { if (has(u, k)) out.rec[k] = st.rec[k] || []; });
    
    const msgs = await MsgModel.find().sort({ _id: -1 }).limit(200);
    res.json({ state: out, msgs: has(u, 'comms') ? msgs.reverse() : [] });
  });

  const S_ = (v, n) => String(v ?? '').slice(0, n);
  const N = v => Number.isFinite(+v) ? +v : 0;
  const arr = a => (Array.isArray(a) ? a : []).filter(x => x && typeof x === 'object');
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
    vehicles: a => arr(a).map(v => ({ pl: S_(v.pl, 40), m: S_(v.m, 100), o: S_(v.o, 2000), imgs: (Array.isArray(v.imgs) ? v.imgs : []).filter(s => typeof s === 'string' && s.length < 1.5e6 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(s)).slice(0, 4) })),
    vault: a => arr(a).slice(0, 1).map(v => { const b = (x, n) => { x = String(x ?? ''); if (!x || x.length > n || !/^[A-Za-z0-9+/=]+$/.test(x)) throw new Error('bad vault'); return x; }; return { s: b(v.s, 64), i: b(v.i, 64), c: b(v.c, 4e6) }; })
  };
  const imgOk = v => v === '' || (typeof v === 'string' && v.length < 3e6 && /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(v));

  app.put('/api/state', auth, async (req, res) => {
    const u = req.user, st = await StateModel.findOne({ key: 'main_state' });
    const rejected = [];
    const recCopy = { ...st.rec };

    for (const [k, v] of Object.entries(req.body || {})) {
      let ok = false;
      if (k === 'threat') { if (has(u, 'sector') && Number.isInteger(v) && v >= 0 && v <= 4) { st.threat = v; ok = true; } }
      else if (k === 'note') { if (has(u, 'sector') && typeof v === 'string') { st.note = v.slice(0, 1000); ok = true; } }
      else if (k === 'org') { if (u.full && typeof v === 'string' && v.trim()) { st.org = v.slice(0, 80); ok = true; } }
      else if (k === 'logo' || k === 'map') { if (u.full && imgOk(v)) { st[k] = v; ok = true; } }
      else if (k === 'board') { if (has(u, 'board') && v && typeof v === 'object' && !Array.isArray(v)) { st.board = san.board(v); ok = true; } }
      else if (k.startsWith('rec.')) {
        const r = k.slice(4);
        if (REC_KEYS.includes(r) && has(u, r) && Array.isArray(v) && v.length <= 2000) { 
          try { recCopy[r] = (san[r] || san.rec)(v); st.rec = recCopy; ok = true; } catch {} 
        }
      } else if (Object.hasOwn(SEC, k) && san[k] && Array.isArray(v) && v.length <= 2000 && has(u, SEC[k])) { st[k] = san[k](v); ok = true; }
      if (!ok) rejected.push(k);
    }
    
    st.markModified('rec');
    await st.save();

    const done = Object.keys(req.body || {}).filter(k => !rejected.includes(k));
    if (done.length) await logEvent(u.u, 'edit: ' + done.join(','));
    res.json({ ok: true, rejected });
  });

  /* ---------- الرسائل ---------- */
  app.get('/api/msgs', auth, async (req, res) => {
    if (!has(req.user, 'comms')) return res.json([]);
    const msgs = await MsgModel.find().sort({ _id: -1 }).limit(200);
    res.json(msgs.reverse());
  });

  app.post('/api/msgs', auth, async (req, res) => {
    if (!has(req.user, 'comms')) return res.status(403).json({ error: 'لا تملك الصلاحية' });
    const x = S_(req.body?.x, 1000).trim();
    if (!x) return res.status(400).json({ error: 'رسالة فارغة' });
    
    await MsgModel.create({
      u: req.user.u,
      c: S_(req.body?.c, 30),
      x,
      t: new Date().toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit', timeZone: process.env.TZ_NAME || 'Asia/Riyadh' })
    });

    const count = await MsgModel.countDocuments();
    if (count > 500) {
      const oldest = await MsgModel.find().sort({ _id: 1 }).limit(count - 500);
      if (oldest.length) {
        await MsgModel.deleteMany({ _id: { $in: oldest.map(x => x._id) } });
      }
    }

    res.json({ ok: true });
  });

  /* ---------- الحسابات (للمسؤول) ---------- */
  const NAME_RE = /^[\w.\-\u0600-\u06FF]{2,32}$/;
  app.get('/api/users', auth, adminOnly, async (req, res) => {
    const users = await UserModel.find();
    res.json(users.map(pub));
  });

  app.post('/api/users', auth, adminOnly, async (req, res) => {
    const { u, p, full, perms } = req.body || {};
    if (typeof u !== 'string' || !NAME_RE.test(u)) return res.status(400).json({ error: 'اسم المستخدم غير صالح (2–32 حرفاً بدون مسافات)' });
    if (typeof p !== 'string' || p.length < 6 || p.length > 200) return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });
    
    const existing = await UserModel.findOne({ u });
    if (existing) return res.status(409).json({ error: 'اسم المستخدم مستخدم مسبقاً' });
    
    await UserModel.create(mkUser(u, p, full, Array.isArray(perms) ? perms : []));
    res.json({ ok: true });
  });

  app.patch('/api/users/:u', auth, adminOnly, async (req, res) => {
    const t = await UserModel.findOne({ u: req.params.u });
    if (!t) return res.status(404).json({ error: 'الحساب غير موجود' });
    
    const { full, perms, p } = req.body || {};
    if (full !== undefined) {
      if (t.u === req.user.u) return res.status(400).json({ error: 'لا يمكنك تغيير صلاحية حسابك' });
      t.full = full ? 1 : 0;
    }
    if (Array.isArray(perms)) t.perms = perms.filter(x => ALL_PERMS.includes(x));
    if (p !== undefined) {
      if (typeof p !== 'string' || p.length < 6 || p.length > 200) return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });
      t.salt = crypto.randomBytes(16).toString('hex'); 
      t.hash = hash(p, t.salt);
    }
    await t.save();
    res.json({ ok: true });
  });

  app.delete('/api/users/:u', auth, adminOnly, async (req, res) => {
    if (req.params.u === req.user.u) return res.status(400).json({ error: 'لا يمكنك حذف حسابك' });
    const result = await UserModel.deleteOne({ u: req.params.u });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'الحساب غير موجود' });
    res.json({ ok: true });
  });

  app.get('/api/audit', auth, adminOnly, async (req, res) => {
    const auditLogs = await AuditModel.find().sort({ t: -1 }).limit(40);
    res.json(auditLogs);
  });

  app.use(express.static(path.join(__dirname, 'public')));
  app.use((err, req, res, next) => err && err.type === 'entity.too.large' ? res.status(413).json({ error: 'حجم البيانات كبير جداً، قلّل عدد الصور' }) : res.status(400).json({ error: 'طلب غير صالح' }));
  
  app.listen(PORT, () => console.log('الخادم يعمل على المنفذ ' + PORT));
}

startServer();