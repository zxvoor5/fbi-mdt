require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

let db;
async function initDb() {
    db = await open({
        filename: path.join(__dirname, 'database.sqlite'),
        driver: sqlite3.Database
    });

    // إنشاء الجداول تلقائياً لو لم تكن موجودة
    await db.exec(`
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            pass_hash TEXT,
            role TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            agent_id INTEGER,
            expires DATETIME
        );
        CREATE TABLE IF NOT EXISTS meta (
            id INTEGER PRIMARY KEY,
            version INTEGER
        );
        INSERT OR IGNORE INTO meta (id, version) VALUES (1, 1);

        CREATE TABLE IF NOT EXISTS citizens (
            ord INTEGER,
            id TEXT,
            name TEXT,
            dob TEXT,
            phone TEXT,
            status TEXT,
            notes TEXT,
            records TEXT
        );
        CREATE TABLE IF NOT EXISTS cases (
            ord INTEGER,
            id TEXT,
            title TEXT,
            pri TEXT,
            status TEXT,
            descr TEXT,
            dt TEXT
        );
        CREATE TABLE IF NOT EXISTS warrants (
            ord INTEGER,
            id TEXT,
            cid TEXT,
            reason TEXT,
            by_agent TEXT,
            dt TEXT
        );
        CREATE TABLE IF NOT EXISTS graph_nodes (
            ord INTEGER,
            id TEXT,
            name TEXT,
            nrole TEXT,
            ntype TEXT,
            status TEXT,
            img TEXT,
            descr TEXT,
            subs TEXT,
            x INTEGER,
            y INTEGER
        );
        CREATE TABLE IF NOT EXISTS graph_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            a TEXT,
            b TEXT
        );
    `);
}

const app = express(), COOKIE = 'mdt_sid';
const w = f => (q, s, n) => f(q, s, n).catch(n);
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((q, s, n) => {
    s.setHeader('X-Content-Type-Options', 'nosniff');
    s.setHeader('X-Frame-Options', 'DENY');
    s.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src * data:; connect-src 'self'");
    n();
});
app.use('/api', (q, s, n) => { s.setHeader('Cache-Control', 'no-store'); n(); });
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const str = (x, n) => String(x ?? '').slice(0, n);
const arr = x => (Array.isArray(x) ? x : []);
const J = v => { try { return Array.isArray(v) ? v : JSON.parse(v || '[]'); } catch (e) { return []; } };
const okU = u => /^[a-z0-9_.-]{2,32}$/.test(u);
const okP = p => typeof p === 'string' && p.length >= 6 && p.length <= 100;

const tries = new Map();
function limited(q) {
    const now = Date.now(), e = tries.get(q.ip) || { n: 0, t: now };
    if (now - e.t > 6e5) { e.n = 0; e.t = now; }
    e.n++; tries.set(q.ip, e);
    return e.n > 10;
}

const cookie = q => { const m = (q.headers.cookie || '').match(/(?:^|;\s*)mdt_sid=([a-f0-9]{64})/); return m && m[1]; };

async function startSession(res, id) {
    const t = crypto.randomBytes(32).toString('hex');
    await db.run('INSERT INTO sessions (token, agent_id, expires) VALUES (?, ?, datetime("now", "+7 days"))', [t, id]);
    res.setHeader('Set-Cookie', `${COOKIE}=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${process.env.COOKIE_SECURE === '1' ? '; Secure' : ''}`);
}

async function getUser(q) {
    const t = cookie(q); if (!t) return null;
    const r = await db.get(`
        SELECT a.id, a.username AS u, a.role 
        FROM sessions s 
        JOIN agents a ON a.id = s.agent_id 
        WHERE s.token = ? AND s.expires > datetime('now')
    `, [t]);
    return r || null;
}

const need = w(async (q, s, n) => {
    const u = await getUser(q);
    if (!u) return s.status(401).json({ error: 'unauthorized' });
    q.user = u; n();
});
const admin = (q, s, n) => (q.user.role === 'admin' ? n() : s.status(403).json({ error: 'forbidden' }));

/* ---------- auth ---------- */
app.get('/api/me', w(async (q, s) => {
    const u = await getUser(q);
    const c = await db.get('SELECT COUNT(*) AS n FROM agents');
    s.json({ user: u ? { u: u.u, role: u.role } : null, needsSetup: c.n === 0 });
}));

app.post('/api/setup', w(async (q, s) => {
    if (limited(q)) return s.status(429).json({ error: 'rate' });
    const c = await db.get('SELECT COUNT(*) AS n FROM agents');
    if (c.n > 0) return s.status(403).json({ error: 'already set up' });
    const u = str(q.body.u, 32).toLowerCase(), p = q.body.p;
    if (!okU(u) || !okP(p)) return s.status(400).json({ error: 'invalid' });
    const res = await db.run('INSERT INTO agents (username, pass_hash, role) VALUES (?, ?, ?)', [u, await bcrypt.hash(p, 10), 'admin']);
    await startSession(s, res.lastID);
    s.json({ user: { u, role: 'admin' } });
}));

app.post('/api/login', w(async (q, s) => {
    if (limited(q)) return s.status(429).json({ error: 'rate' });
    const u = str(q.body.u, 32).toLowerCase(), p = str(q.body.p, 100);
    const a = await db.get('SELECT id, pass_hash, role FROM agents WHERE username = ?', [u]);
    if (!a || !(await bcrypt.compare(p, a.pass_hash))) return s.status(401).json({ error: 'bad credentials' });
    await startSession(s, a.id);
    s.json({ user: { u, role: a.role } });
}));

app.post('/api/logout', w(async (q, s) => {
    const t = cookie(q);
    if (t) await db.run('DELETE FROM sessions WHERE token = ?', [t]);
    s.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
    s.json({ ok: 1 });
}));

/* ---------- agents ---------- */
app.get('/api/agents', need, admin, w(async (q, s) => {
    const r = await db.all('SELECT username AS u, role FROM agents ORDER BY id');
    s.json({ agents: r });
}));
app.post('/api/agents', need, admin, w(async (q, s) => {
    const u = str(q.body.u, 32).toLowerCase(), p = q.body.p, role = q.body.role === 'admin' ? 'admin' : 'agent';
    if (!okU(u) || !okP(p)) return s.status(400).json({ error: 'invalid' });
    try {
        await db.run('INSERT INTO agents (username, pass_hash, role) VALUES (?, ?, ?)', [u, await bcrypt.hash(p, 10), role]);
    } catch (e) {
        if (e.message.includes('UNIQUE')) return s.status(409).json({ error: 'exists' });
        throw e;
    }
    s.json({ ok: 1 });
}));
app.delete('/api/agents/:u', need, admin, w(async (q, s) => {
    const u = String(q.params.u).toLowerCase();
    if (u === q.user.u) return s.status(400).json({ error: 'cannot delete yourself' });
    await db.run('DELETE FROM agents WHERE username = ?', [u]);
    s.json({ ok: 1 });
}));

/* ---------- data ---------- */
app.get('/api/version', need, w(async (q, s) => {
    const m = await db.get('SELECT version FROM meta WHERE id = 1');
    s.json({ version: Number(m.version) });
}));

app.get('/api/data', need, w(async (q, s) => {
    const m = await db.get('SELECT version FROM meta WHERE id = 1');
    const ci = await db.all('SELECT * FROM citizens ORDER BY ord');
    const ca = await db.all('SELECT * FROM cases ORDER BY ord');
    const wa = await db.all('SELECT * FROM warrants ORDER BY ord');
    const no = await db.all('SELECT * FROM graph_nodes ORDER BY ord');
    const ed = await db.all('SELECT a, b FROM graph_edges ORDER BY id');
    const v = Number(m.version);
    s.json({
        version: v, fresh: v === 0,
        citizens: ci.map(x => ({ id: x.id, name: x.name, dob: x.dob, phone: x.phone, status: x.status, notes: x.notes || '', records: J(x.records) })),
        cases: ca.map(x => ({ id: x.id, title: x.title, pri: x.pri, status: x.status, desc: x.descr || '', date: x.dt })),
        warrants: wa.map(x => ({ id: x.id, cid: x.cid, reason: x.reason, by: x.by_agent, date: x.dt })),
        graph: {
            nodes: no.map(x => ({ id: x.id, name: x.name, role: x.nrole || '', type: x.ntype, status: x.status, img: x.img || '', desc: x.descr || '', subs: J(x.subs), x: x.x, y: x.y })),
            edges: ed.map(x => ({ a: x.a, b: x.b }))
        }
    });
}));

app.put('/api/data', need, w(async (q, s) => {
    const b = q.body || {};
    await db.exec('BEGIN TRANSACTION;');
    try {
        await db.exec('DELETE FROM warrants; DELETE FROM citizens; DELETE FROM cases; DELETE FROM graph_edges; DELETE FROM graph_nodes;');

        const citizens = arr(b.citizens).slice(0, 5000);
        for (let i = 0; i < citizens.length; i++) {
            let x = citizens[i];
            await db.run('INSERT INTO citizens (ord, id, name, dob, phone, status, notes, records) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [i, str(x.id, 40), str(x.name, 120), str(x.dob, 20), str(x.phone, 40), str(x.status, 20), str(x.notes, 5000), JSON.stringify(arr(x.records).map(r => str(r, 500)))]);
        }

        const cases = arr(b.cases).slice(0, 5000);
        for (let i = 0; i < cases.length; i++) {
            let x = cases[i];
            await db.run('INSERT INTO cases (ord, id, title, pri, status, descr, dt) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [i, str(x.id, 40), str(x.title, 200), str(x.pri, 10), str(x.status, 10), str(x.desc, 5000), str(x.date, 20)]);
        }

        const warrants = arr(b.warrants).slice(0, 5000);
        for (let i = 0; i < warrants.length; i++) {
            let x = warrants[i];
            await db.run('INSERT INTO warrants (ord, id, cid, reason, by_agent, dt) VALUES (?, ?, ?, ?, ?, ?)',
                [i, str(x.id, 40), str(x.cid, 40), str(x.reason, 2000), str(x.by, 60), str(x.date, 20)]);
        }

        const nodes = arr(b.graph && b.graph.nodes).slice(0, 2000);
        for (let i = 0; i < nodes.length; i++) {
            let x = nodes[i];
            await db.run('INSERT INTO graph_nodes (ord, id, name, nrole, ntype, status, img, descr, subs, x, y) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [i, str(x.id, 40), str(x.name, 120), str(x.role, 120), str(x.type, 20), str(x.status, 20), str(x.img, 500), str(x.desc, 5000), JSON.stringify(arr(x.subs).map(t => str(t, 120))), Math.round(Number(x.x)) || 0, Math.round(Number(x.y)) || 0]);
        }

        const nodeIds = new Set(nodes.map(x => str(x.id, 40)));
        const edges = arr(b.graph && b.graph.edges).filter(e => nodeIds.has(str(e.a, 40)) && nodeIds.has(str(e.b, 40))).slice(0, 10000);
        for (let e of edges) {
            await db.run('INSERT INTO graph_edges (a, b) VALUES (?, ?)', [str(e.a, 40), str(e.b, 40)]);
        }

        await db.run('UPDATE meta SET version = version + 1 WHERE id = 1');
        const m = await db.get('SELECT version FROM meta WHERE id = 1');
        await db.exec('COMMIT;');
        s.json({ version: Number(m.version) });
    } catch (e) {
        await db.exec('ROLLBACK;');
        throw e;
    }
}));

app.use((e, q, s, n) => { console.error(e); s.status(500).json({ error: 'server error' }); });

setInterval(() => db.run('DELETE FROM sessions WHERE expires < datetime("now")').catch(() => {}), 36e5);

initDb().then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log('FBI MDT running with SQLite on port ' + PORT));
});