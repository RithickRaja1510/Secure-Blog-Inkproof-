'use strict';
/**
 * Attack-simulation tests. Each test plays the attacker and asserts the defence holds.
 * Run with: npm test
 */
const { test, before, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/server');
const { hashPassword } = require('../src/security');

let inst;
let base;

const OUR_SCRIPT = '<script src="/app.js" defer></script>';
/** Page markup with our one legitimate script tag removed, so any <script> left over is an injection. */
const clean = (markup) => markup.replace(OUR_SCRIPT, '');

/** Real HTML tags that carry an inline event handler, inline style or javascript: URL (quote-aware). */
function dangerousTags(markup) {
  const tags = markup.match(/<[a-zA-Z](?:"[^"]*"|'[^']*'|[^>"'])*>/g) || [];
  return tags.filter((t) => {
    const bare = t.replace(/"[^"]*"|'[^']*'/g, '""'); // drop attribute values: text in there is inert
    return /\s(on[a-z]+|style)\s*=/i.test(bare) || /(href|src|action)\s*=\s*["']?\s*javascript:/i.test(t);
  });
}

class Client {
  constructor() {
    this.jar = new Map();
  }
  async req(method, path, { form, raw, headers = {}, origin = true } = {}) {
    const h = { ...headers };
    const cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
    if (cookie) h.cookie = cookie;
    let body;
    if (form !== undefined) {
      h['content-type'] = h['content-type'] || 'application/x-www-form-urlencoded';
      body = typeof form === 'string' ? form : new URLSearchParams(form).toString();
    }
    if (raw) { h['content-type'] = raw.type; body = raw.body; }
    if (method === 'POST' && origin) h.origin = origin === true ? base : origin;
    const res = await fetch(base + path, { method, headers: h, body, redirect: 'manual' });
    for (const sc of res.headers.getSetCookie()) {
      const [pair] = sc.split(';');
      const i = pair.indexOf('=');
      const k = pair.slice(0, i);
      const v = pair.slice(i + 1);
      if (/max-age=0/i.test(sc)) this.jar.delete(k); else this.jar.set(k, v);
    }
    const text = await res.text();
    return { status: res.status, headers: res.headers, text, location: res.headers.get('location'), setCookie: res.headers.getSetCookie() };
  }
  get(path) { return this.req('GET', path); }
  post(path, form, opts) { return this.req('POST', path, { form, ...opts }); }
  async token(path) {
    const r = await this.get(path);
    const m = /name="_csrf" value="([^"]+)"/.exec(r.text);
    assert.ok(m, `no CSRF token on ${path} (status ${r.status})`);
    return m[1];
  }
  /** Load a page to obtain a token (as a browser would), then submit the form with it. */
  async submit(pagePath, postPath, form) {
    return this.post(postPath, { ...form, _csrf: await this.token(pagePath) });
  }
  async submitMultipart(pagePath, postPath, fields, file, opts = {}) {
    const token = await this.token(pagePath);
    return this.req('POST', postPath, { raw: multipart({ ...fields, _csrf: token }, file), ...opts });
  }
  async register(username, password = 'correct horse battery') {
    const r = await this.submit('/register', '/register', { username, password });
    assert.equal(r.status, 303, `register failed: ${r.status}`);
    return r;
  }
  async createPost(title, body, published = '1') {
    const r = await this.submit('/new', '/new', { title, body, published });
    assert.equal(r.status, 303, `createPost failed: ${r.status}`);
    return Number(/\/post\/(\d+)/.exec(r.location)[1]);
  }
}

/** Build a multipart/form-data body by hand (text fields plus at most one file). */
function multipart(fields, file) {
  const b = `----inkproof${Math.random().toString(16).slice(2)}`;
  const parts = [];
  for (const [k, v] of Object.entries(fields)) {
    parts.push(Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
  }
  if (file) {
    parts.push(Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="${file.field || 'cover'}"; filename="${file.filename || 'x.png'}"\r\nContent-Type: ${file.type || 'image/png'}\r\n\r\n`));
    parts.push(file.data, Buffer.from('\r\n'));
  }
  parts.push(Buffer.from(`--${b}--\r\n`));
  return { body: Buffer.concat(parts), type: `multipart/form-data; boundary=${b}` };
}

before(async () => {
  inst = createApp({
    dbFile: ':memory:', quiet: true,
    rate: { global: [100000, 60000], register: [1000, 60000], react: [10000, 60000], search: [10000, 60000] },
  });
  const addr = await inst.listen(0, '127.0.0.1');
  base = `http://127.0.0.1:${addr.port}`;
});
after(async () => { await inst.close(); });

/* ================================================================== */
describe('XSS', () => {
  const PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    "'-alert(1)-'",
    '<a href="javascript:alert(1)">x</a>',
  ];

  test('stored XSS in post title and body is neutralised', async () => {
    const c = new Client();
    await c.register('xss_author');
    for (const p of PAYLOADS) {
      const id = await c.createPost(`T ${p}`, `body ${p}\n\n[click](javascript:alert(1)) [ok](https://example.com/a?b=1&c=2)`);
      const page = await c.get(`/post/${id}`);
      assert.equal(page.status, 200);
      assert.ok(!/<script[\s>]/i.test(clean(page.text)), `script tag survived for ${p}`);
      assert.ok(!/<img[\s>]/i.test(page.text), `img tag survived for ${p}`);
      assert.ok(!/<svg[^>]*\son[a-z]+\s*=/i.test(page.text), 'injected <svg onload> survived');
      assert.deepEqual(dangerousTags(page.text), [], `dangerous markup for ${p}`);
      assert.ok(!/href="javascript:/i.test(page.text), 'javascript: link rendered');
      assert.ok(page.text.includes('href="https://example.com/a?b=1&amp;c=2"'), 'legitimate link should still work');
    }
  });

  test('home page listing escapes titles and excerpts too', async () => {
    const c = new Client();
    const r = await c.get('/');
    assert.ok(!/<script[\s>]/i.test(clean(r.text)));
    assert.ok(r.text.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  });

  test('stored XSS in comments is neutralised', async () => {
    const c = new Client();
    await c.register('xss_commenter');
    const id = await c.createPost('Comment target', 'hello');
    for (const p of PAYLOADS) {
      const r = await c.submit(`/post/${id}`, `/post/${id}/comments`, { body: p });
      assert.equal(r.status, 303);
    }
    const page = await c.get(`/post/${id}`);
    assert.ok(!/<script[\s>]/i.test(clean(page.text)));
    assert.ok(!/<img[\s>]/i.test(page.text));
    assert.ok(!/<svg[^>]*\son[a-z]+\s*=/i.test(page.text), 'injected <svg onload> survived');
    assert.ok(!/<a href="javascript:/i.test(page.text));
    assert.ok(page.text.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  });

  test('reflected input in form re-display is escaped (attribute breakout)', async () => {
    const c = new Client();
    const r = await c.submit('/register', '/register', { username: '"><script>alert(1)</script>', password: 'correct horse battery' });
    assert.equal(r.status, 422);
    assert.ok(!/<script[\s>]/i.test(clean(r.text)));
    assert.ok(r.text.includes('&quot;&gt;&lt;script&gt;'));
  });

  test('restricted markup cannot be abused: URLs with credentials or odd schemes are not linked', async () => {
    const c = new Client();
    await c.register('markup_user');
    const id = await c.createPost('Links', '[a](https://user:pass@evil.example/) [b](data:text/html,<script>alert(1)</script>) [c](HTTPS://Example.com)');
    const page = await c.get(`/post/${id}`);
    assert.ok(!page.text.includes('evil.example/"'));
    assert.ok(!/href="data:/i.test(page.text));
    assert.ok(/href="https:\/\/example\.com\/"/.test(page.text));
  });

  test('responses carry a strict CSP (own-origin scripts only), plus other hardening headers', async () => {
    const r = await new Client().get('/');
    const csp = r.headers.get('content-security-policy');
    assert.match(csp, /script-src 'self'(;|$)/);
    assert.ok(!/unsafe-inline|unsafe-eval|\*/.test(csp), 'CSP must not allow inline/eval/wildcards');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /base-uri 'none'/);
    assert.match(csp, /form-action 'self'/);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    // Must stay 'same-origin': 'no-referrer' makes browsers send "Origin: null" on our own forms (CSRF check would block them).
    assert.equal(r.headers.get('referrer-policy'), 'same-origin');
    assert.match(r.headers.get('content-type'), /charset=utf-8/i);
  });

  test('no inline script, inline style or event-handler attributes in any page we serve', async () => {
    const c = new Client();
    await c.register('inline_check');
    const id = await c.createPost('Inline check', 'text');
    for (const p of ['/', '/login', `/post/${id}`, '/new', '/dashboard']) {
      const r = await c.get(p);
      assert.ok(!/<script/i.test(clean(r.text)), `inline <script> in ${p}`);
      // Inspect real tags only: user text is escaped, so any '<' in the output starts one of OUR tags.
      assert.deepEqual(dangerousTags(r.text), [], `inline style/event handler in ${p}`);
    }
  });
});

/* ================================================================== */
describe('CSRF', () => {
  test('POST without token is rejected', async () => {
    const c = new Client();
    await c.register('csrf_victim1');
    const r = await c.post('/new', { title: 'forged', body: 'forged', published: '1' });
    assert.equal(r.status, 403);
  });

  test('POST with a wrong or empty token is rejected', async () => {
    const c = new Client();
    await c.register('csrf_victim2');
    await c.get('/new');
    for (const t of ['', 'abc', 'A'.repeat(43)]) {
      const r = await c.post('/new', { title: 'forged', body: 'forged', _csrf: t });
      assert.equal(r.status, 403, `token "${t}" accepted`);
    }
  });

  test("a token from another user's session is rejected", async () => {
    const a = new Client();
    const b = new Client();
    await a.register('csrf_a');
    await b.register('csrf_b');
    const tokenOfA = await a.token('/new');
    const r = await b.post('/new', { title: 'x', body: 'y', _csrf: tokenOfA });
    assert.equal(r.status, 403);
  });

  test('valid token but cross-site Origin is rejected', async () => {
    const c = new Client();
    await c.register('csrf_origin');
    const token = await c.token('/new');
    for (const origin of ['https://evil.example', 'http://127.0.0.1:1', 'null']) {
      const r = await c.post('/new', { title: 'x', body: 'y', _csrf: token }, { origin });
      assert.equal(r.status, 403, `origin ${origin} accepted`);
    }
  });

  test('request with neither Origin nor Referer is rejected; same-origin Referer is accepted', async () => {
    const c = new Client();
    await c.register('csrf_referer');
    const token = await c.token('/new');
    const none = await c.post('/new', { title: 'x', body: 'y', _csrf: token }, { origin: false });
    assert.equal(none.status, 403);
    const ok = await c.post('/new', { title: 'x', body: 'y', _csrf: token }, { origin: false, headers: { referer: `${base}/new` } });
    assert.equal(ok.status, 303);
  });

  test('login and logout are protected as well (login CSRF / forced logout)', async () => {
    const c = new Client();
    await c.register('csrf_logout');
    const r = await c.post('/logout', {});
    assert.equal(r.status, 403);
    assert.equal((await c.get('/dashboard')).status, 200, 'still logged in');
    const anon = new Client();
    await anon.get('/login');
    const l = await anon.post('/login', { username: 'csrf_logout', password: 'correct horse battery' });
    assert.equal(l.status, 403);
  });

  test('state-changing GET requests do not exist', async () => {
    const c = new Client();
    await c.register('csrf_get');
    const id = await c.createPost('Keep me', 'content');
    for (const p of [`/post/${id}/delete`, '/logout']) {
      const r = await c.get(p);
      assert.ok([404, 405].includes(r.status), `${p} -> ${r.status}`);
    }
    assert.equal((await c.get(`/post/${id}`)).status, 200);
  });

  test('session cookie is HttpOnly + SameSite=Strict', async () => {
    const c = new Client();
    const r = await c.get('/login');
    const sc = r.setCookie.find((s) => s.startsWith('sid='));
    assert.ok(sc, 'session cookie set');
    assert.match(sc, /HttpOnly/i);
    assert.match(sc, /SameSite=Strict/i);
    assert.match(sc, /Path=\//);
  });
});

/* ================================================================== */
describe('Authentication and sessions', () => {
  test('passwords are stored as salted scrypt hashes', async () => {
    const c = new Client();
    await c.register('hash_check', 'a-very-long-passphrase');
    const row = inst.db.prepare('SELECT password_hash FROM users WHERE username = ?').get('hash_check');
    assert.match(row.password_hash, /^scrypt\$16384\$8\$1\$/);
    assert.ok(!row.password_hash.includes('a-very-long-passphrase'));
  });

  test('session id is regenerated on login (session fixation)', async () => {
    const c = new Client();
    await c.register('fixation_user');
    await c.post('/logout', { _csrf: await c.token('/dashboard') });
    const before = (await c.get('/login')).setCookie.find((s) => s.startsWith('sid=')).split(';')[0];
    const token = await c.token('/login');
    const r = await c.post('/login', { username: 'fixation_user', password: 'correct horse battery', _csrf: token });
    assert.equal(r.status, 303);
    const after = r.setCookie.find((s) => s.startsWith('sid=')).split(';')[0];
    assert.notEqual(before, after);
    const old = new Client();
    old.jar.set('sid', before.slice(4));
    assert.equal((await old.get('/dashboard')).status, 303, 'old session id must not be logged in');
  });

  test('session ids are not stored in the database in usable form', async () => {
    const c = new Client();
    await c.register('hashed_sid');
    const sid = c.jar.get('sid');
    const rows = inst.db.prepare('SELECT id_hash FROM sessions').all();
    assert.ok(rows.length > 0);
    assert.ok(!rows.some((r) => r.id_hash === sid));
  });

  test('logout invalidates the session server-side', async () => {
    const c = new Client();
    await c.register('logout_user');
    const sid = c.jar.get('sid');
    const r = await c.post('/logout', { _csrf: await c.token('/dashboard') });
    assert.equal(r.status, 303);
    const replay = new Client();
    replay.jar.set('sid', sid);
    assert.equal((await replay.get('/dashboard')).status, 303);
  });

  test('login errors are generic (no user enumeration)', async () => {
    const c = new Client();
    await c.register('enum_user');
    const anon = new Client();
    const a = await anon.submit('/login', '/login', { username: 'enum_user', password: 'wrong-password-1' });
    const b = await anon.submit('/login', '/login', { username: 'nobody_here', password: 'wrong-password-1' });
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.ok(a.text.includes('Invalid username or password.'));
    assert.ok(b.text.includes('Invalid username or password.'));
  });

  test('brute force is throttled', async () => {
    const c = new Client();
    await c.register('brute_target');
    const anon = new Client();
    const statuses = [];
    for (let i = 0; i < 7; i++) {
      statuses.push((await anon.submit('/login', '/login', { username: 'brute_target', password: `guess-number-${i}-xx` })).status);
    }
    assert.deepEqual(statuses.slice(0, 5), [401, 401, 401, 401, 401]);
    assert.equal(statuses[5], 429);
    // even the right password is refused while locked out
    const right = await anon.submit('/login', '/login', { username: 'brute_target', password: 'correct horse battery' });
    assert.equal(right.status, 429);
  });

  test('weak passwords and bad usernames are rejected', async () => {
    const c = new Client();
    const short = await c.submit('/register', '/register', { username: 'weakpw_user', password: 'short' });
    assert.equal(short.status, 422);
    const bad = await c.submit('/register', '/register', { username: "x' OR 1=1 --", password: 'correct horse battery' });
    assert.equal(bad.status, 422);
  });
});

/* ================================================================== */
describe('Unauthorised content modification', () => {
  let alice;
  let bob;
  let postId;
  let aliceDraftId;
  let bobCommentId;

  before(async () => {
    alice = new Client();
    bob = new Client();
    await alice.register('alice_owner');
    await bob.register('bob_other');
    postId = await alice.createPost('Alice original', 'Alice text');
    aliceDraftId = await alice.createPost('Alice draft', 'secret draft', '');
    const r = await bob.submit(`/post/${postId}`, `/post/${postId}/comments`, { body: 'Bob comment' });
    assert.equal(r.status, 303);
    bobCommentId = Number(/#c(\d+)/.exec(r.location)[1]);
  });

  const titleOf = (id) => inst.db.prepare('SELECT title FROM posts WHERE id = ?').get(id);

  test('anonymous visitors cannot create, edit or delete (redirected to login)', async () => {
    const anon = new Client();
    await anon.get('/login'); // obtains a session + token like any browser
    const token = await anon.token('/login');
    for (const p of ['/new', `/post/${postId}/edit`, `/post/${postId}/delete`, `/post/${postId}/comments`]) {
      const r = await anon.post(p, { title: 'x', body: 'y', _csrf: token });
      assert.equal(r.status, 303, p);
      assert.equal(r.location, '/login', p);
    }
    assert.equal(titleOf(postId).title, 'Alice original');
  });

  test("another user cannot edit someone else's post (GET form and POST)", async () => {
    const token = await bob.token('/new');
    assert.equal((await bob.get(`/post/${postId}/edit`)).status, 403);
    const r = await bob.post(`/post/${postId}/edit`, { title: 'HACKED', body: 'HACKED', published: '1', _csrf: token });
    assert.equal(r.status, 403);
    assert.equal(titleOf(postId).title, 'Alice original');
  });

  test("another user cannot delete someone else's post", async () => {
    const token = await bob.token('/new');
    const r = await bob.post(`/post/${postId}/delete`, { _csrf: token });
    assert.equal(r.status, 403);
    assert.ok(titleOf(postId));
  });

  test('hidden-field tampering (author_id, role, id) is ignored (mass assignment)', async () => {
    const aliceRow = inst.db.prepare("SELECT id FROM users WHERE username = 'alice_owner'").get();
    const token = await bob.token('/new');
    const r = await bob.post('/new', { title: 'Bob post', body: 'x', published: '1', author_id: String(aliceRow.id), role: 'admin', id: String(postId), _csrf: token });
    assert.equal(r.status, 303);
    const id = Number(/\/post\/(\d+)/.exec(r.location)[1]);
    assert.notEqual(id, postId);
    const row = inst.db.prepare('SELECT p.author_id, u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = ?').get(id);
    assert.equal(row.username, 'bob_other');
    assert.equal(inst.db.prepare("SELECT role FROM users WHERE username = 'bob_other'").get().role, 'user');
  });

  test("drafts are invisible to others and look like 404 (no existence leak)", async () => {
    assert.equal((await bob.get(`/post/${aliceDraftId}`)).status, 404);
    assert.equal((await new Client().get(`/post/${aliceDraftId}`)).status, 404);
    assert.equal((await bob.get(`/post/${aliceDraftId}/edit`)).status, 404);
    assert.ok(!(await new Client().get('/')).text.includes('Alice draft'));
    assert.equal((await alice.get(`/post/${aliceDraftId}`)).status, 200);
  });

  test('comment edit: only the author; post owner and others are refused', async () => {
    const tA = await alice.token('/new');
    assert.equal((await alice.get(`/comment/${bobCommentId}/edit`)).status, 403);
    const r = await alice.post(`/comment/${bobCommentId}/edit`, { body: 'Alice rewrote bob', _csrf: tA });
    assert.equal(r.status, 403);
    assert.equal(inst.db.prepare('SELECT body FROM comments WHERE id = ?').get(bobCommentId).body, 'Bob comment');
    const tB = await bob.token(`/comment/${bobCommentId}/edit`);
    const ok = await bob.post(`/comment/${bobCommentId}/edit`, { body: 'Bob edited', _csrf: tB });
    assert.equal(ok.status, 303);
    assert.equal(inst.db.prepare('SELECT body FROM comments WHERE id = ?').get(bobCommentId).body, 'Bob edited');
  });

  test('a third user cannot delete a comment; the post owner (moderation) and the author can', async () => {
    const eve = new Client();
    await eve.register('eve_third');
    const tE = await eve.token('/new');
    assert.equal((await eve.post(`/comment/${bobCommentId}/delete`, { _csrf: tE })).status, 403);
    assert.ok(inst.db.prepare('SELECT 1 FROM comments WHERE id = ?').get(bobCommentId));

    const mod = await alice.token('/dashboard');
    assert.equal((await alice.post(`/comment/${bobCommentId}/delete`, { _csrf: mod })).status, 303);
    assert.equal(inst.db.prepare('SELECT 1 FROM comments WHERE id = ?').get(bobCommentId), undefined);
  });

  test('admin may delete any post; normal owner may edit and delete their own', async () => {
    const owner = new Client();
    await owner.register('owner_ok');
    const id = await owner.createPost('Mine', 'v1');
    const e = await owner.submit(`/post/${id}/edit`, `/post/${id}/edit`, { title: 'Mine v2', body: 'v2', published: '1' });
    assert.equal(e.status, 303);
    assert.equal(titleOf(id).title, 'Mine v2');

    inst.models.createUser('root_admin', await hashPassword('admin password long'), 'admin');
    const admin = new Client();
    const t = await admin.token('/login');
    assert.equal((await admin.post('/login', { username: 'root_admin', password: 'admin password long', _csrf: t })).status, 303);
    assert.equal((await admin.submit('/dashboard', `/post/${id}/delete`, {})).status, 303);
    assert.equal(titleOf(id), undefined);

    const audit = await admin.get('/admin/audit');
    assert.equal(audit.status, 200);
    assert.ok(audit.text.includes('denied:post_edit'));
    assert.equal((await alice.get('/admin/audit')).status, 403);
  });

  test('IDs are validated: injection-style and out-of-range ids do not reach the database', async () => {
    for (const p of ['/post/1%20OR%201=1', "/post/1'", '/post/-1', '/post/99999999999', '/post/abc', '/post/0']) {
      const r = await alice.get(p);
      assert.ok([404].includes(r.status), `${p} -> ${r.status}`);
    }
  });

  test('SQL injection payloads are stored as inert text', async () => {
    const evil = "Robert'); DROP TABLE posts;--";
    const id = await alice.createPost(evil, "' OR '1'='1");
    const page = await alice.get(`/post/${id}`);
    assert.ok(page.text.includes('Robert&#39;); DROP TABLE posts;--'));
    assert.ok(inst.db.prepare('SELECT COUNT(*) AS n FROM posts').get().n > 1);
  });

  test('modifications are written to the audit log', async () => {
    const rows = inst.models.recentAudit(500).map((r) => r.action);
    for (const a of ['post_create', 'post_update', 'post_delete', 'comment_create', 'comment_update', 'comment_delete', 'denied:post_edit']) {
      assert.ok(rows.includes(a), `missing audit action ${a}`);
    }
  });
});

/* ================================================================== */
describe('Robustness', () => {
  test('oversized bodies are rejected with 413', async () => {
    const c = new Client();
    await c.register('big_body');
    const token = await c.token('/new');
    const r = await c.post('/new', `title=x&body=${'a'.repeat(70 * 1024)}&_csrf=${token}`);
    assert.equal(r.status, 413);
  });

  test('over-long fields are rejected with validation errors', async () => {
    const c = new Client();
    await c.register('long_fields');
    const r = await c.submit('/new', '/new', { title: 'T'.repeat(151), body: 'ok' });
    assert.equal(r.status, 422);
    const r2 = await c.submit('/new', '/new', { title: 'ok', body: 'x'.repeat(20001) });
    assert.equal(r2.status, 422);
  });

  test('non-form content types are rejected with 415', async () => {
    const c = new Client();
    await c.register('ctype_user');
    const r = await c.post('/new', '{"title":"x"}', { headers: { 'content-type': 'application/json' } });
    assert.equal(r.status, 415);
  });

  test('unknown methods and paths; no stack traces or path traversal', async () => {
    const c = new Client();
    assert.equal((await c.req('DELETE', '/')).status, 405);
    assert.equal((await c.req('PUT', '/post/1')).status, 405);
    assert.equal((await c.get('/nope')).status, 404);
    for (const p of ['/../../etc/passwd', '/%2e%2e/%2e%2e/etc/passwd', '/style.css/../../package.json', '/src/server.js', '/package.json']) {
      const r = await c.get(p);
      assert.equal(r.status, 404, p);
      assert.ok(!/root:|require\(|node_modules/.test(r.text), p);
    }
  });

  test('control and bidi-override characters are stripped from titles', async () => {
    const c = new Client();
    await c.register('bidi_user');
    const id = await c.createPost('Hello‮evil\u0000world', 'body');
    const row = inst.db.prepare('SELECT title FROM posts WHERE id = ?').get(id);
    assert.equal(row.title, 'Helloevilworld');
  });
});

/* ================================================================== */
/* New features: every one of them gets attacked too                   */
/* ================================================================== */

const fs = require('node:fs');

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const png = (extra = 64) => ({ data: Buffer.concat([PNG_MAGIC, Buffer.alloc(extra, 7)]), filename: 'cover.png', type: 'image/png' });
const filesOnDisk = () => fs.readdirSync(inst.app.uploads.dir).sort();
const coverOf = (html) => (/\/uploads\/([a-f0-9]{32}\.[a-z]+)/.exec(html) || [])[1];

async function postWithCover(client, fields, file) {
  const r = await client.submitMultipart('/new', '/new', { published: '1', ...fields }, file);
  return { r, id: r.status === 303 ? Number(/\/post\/(\d+)/.exec(r.location)[1]) : null };
}

describe('Image uploads', () => {
  test('a real image is accepted, stored under a random name and served with locked-down headers', async () => {
    const c = new Client();
    await c.register('up_ok');
    const { r, id } = await postWithCover(c, { title: 'With cover', body: 'x' }, { ...png(), filename: '../../../evil.html' });
    assert.equal(r.status, 303);
    const name = coverOf((await c.get(`/post/${id}`)).text);
    assert.match(name, /^[a-f0-9]{32}\.png$/, 'client file name must be ignored');
    const img = await new Client().get(`/uploads/${name}`);
    assert.equal(img.status, 200);
    assert.equal(img.headers.get('content-type'), 'image/png');
    assert.equal(img.headers.get('x-content-type-options'), 'nosniff');
    assert.match(img.headers.get('content-security-policy'), /sandbox/);
  });

  test('HTML or SVG disguised as an image is rejected (type comes from the bytes, not the name)', async () => {
    const c = new Client();
    await c.register('up_fake');
    const before = filesOnDisk();
    const fakes = [
      Buffer.from('<html><script>alert(1)</script></html>'.padEnd(40, ' ')),
      Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'),
      Buffer.from('MZ'.padEnd(64, '\0')),
    ];
    for (const data of fakes) {
      const { r } = await postWithCover(c, { title: 'Fake', body: 'x' }, { data, filename: 'evil.png', type: 'image/png' });
      assert.equal(r.status, 422);
      assert.ok(r.text.includes('Only PNG, JPG, GIF or WebP'));
    }
    assert.deepEqual(filesOnDisk(), before, 'nothing may be written for a rejected upload');
  });

  test('a script hidden inside a GIF is served as an image, never as HTML', async () => {
    const c = new Client();
    await c.register('up_poly');
    const data = Buffer.concat([Buffer.from('GIF89a'), Buffer.from('<script>alert(1)</script>'), Buffer.alloc(30)]);
    const { r, id } = await postWithCover(c, { title: 'Polyglot', body: 'x' }, { data, filename: 'a.gif', type: 'image/gif' });
    assert.equal(r.status, 303);
    const name = coverOf((await c.get(`/post/${id}`)).text);
    const img = await c.get(`/uploads/${name}`);
    assert.equal(img.headers.get('content-type'), 'image/gif');
    assert.equal(img.headers.get('x-content-type-options'), 'nosniff');
    assert.match(img.headers.get('content-security-policy'), /default-src 'none'/);
  });

  test('size limits: slightly too big gets a friendly error, far too big is refused outright', async () => {
    const c = new Client();
    await c.register('up_big');
    const mid = await postWithCover(c, { title: 'Big', body: 'x' }, png(1_600_000));
    assert.equal(mid.r.status, 422);
    assert.ok(mid.r.text.includes('larger than 1.5 MB'));
    const huge = await postWithCover(c, { title: 'Huge', body: 'x' }, png(1_800_000));
    assert.equal(huge.r.status, 413);
  });

  test('uploaded file names cannot be used for path traversal', async () => {
    const c = new Client();
    for (const p of [
      '/uploads/..%2f..%2fetc%2fpasswd', '/uploads/%2e%2e/%2e%2e/package.json',
      '/uploads/00000000000000000000000000000000.png', '/uploads/../src/server.js', '/uploads/x.html',
    ]) {
      assert.equal((await c.get(p)).status, 404, p);
    }
  });

  test("a draft's cover image is private to its author", async () => {
    const alice = new Client();
    const bob = new Client();
    await alice.register('up_alice');
    await bob.register('up_bob');
    const { id } = await postWithCover(alice, { title: 'Secret draft', body: 'x', published: '' }, png());
    const name = coverOf((await alice.get(`/post/${id}`)).text);
    assert.equal((await alice.get(`/uploads/${name}`)).status, 200);
    assert.equal((await bob.get(`/uploads/${name}`)).status, 404);
    assert.equal((await new Client().get(`/uploads/${name}`)).status, 404);
  });

  test("another user cannot replace or remove someone else's cover, and no file is written", async () => {
    const alice = new Client();
    const bob = new Client();
    await alice.register('cov_alice');
    await bob.register('cov_bob');
    const { id } = await postWithCover(alice, { title: 'Alice cover', body: 'x' }, png());
    const before = filesOnDisk();
    const r = await bob.submitMultipart('/new', `/post/${id}/edit`, { title: 'HACK', body: 'HACK', published: '1', remove_cover: '1' }, png());
    assert.equal(r.status, 403);
    assert.deepEqual(filesOnDisk(), before);
    assert.equal(inst.db.prepare('SELECT title FROM posts WHERE id = ?').get(id).title, 'Alice cover');
    assert.ok(coverOf((await alice.get(`/post/${id}`)).text));
  });

  test('replacing a cover deletes the old file; deleting the post deletes the cover', async () => {
    const c = new Client();
    await c.register('cov_owner');
    const { id } = await postWithCover(c, { title: 'Cover life', body: 'x' }, png());
    const first = coverOf((await c.get(`/post/${id}`)).text);
    assert.ok(filesOnDisk().includes(first));
    const r = await c.submitMultipart(`/post/${id}/edit`, `/post/${id}/edit`, { title: 'Cover life', body: 'x', published: '1' }, png(80));
    assert.equal(r.status, 303);
    const second = coverOf((await c.get(`/post/${id}`)).text);
    assert.notEqual(first, second);
    assert.ok(!filesOnDisk().includes(first), 'old cover must be removed');
    assert.equal((await c.submit('/dashboard', `/post/${id}/delete`, {})).status, 303);
    assert.ok(!filesOnDisk().includes(second), 'cover must be removed with its post');
  });

  test('hostile titles cannot break out of the cover image alt attribute', async () => {
    const c = new Client();
    await c.register('alt_user');
    const { id } = await postWithCover(c, { title: '" onerror="alert(1)" x="', body: 'x' }, png());
    const page = await c.get(`/post/${id}`);
    assert.deepEqual(dangerousTags(page.text), []);
    assert.ok(page.text.includes('&quot; onerror=&quot;alert(1)&quot;'));
  });

  test('multipart is only accepted on the two upload routes; malformed bodies get a clean 400', async () => {
    const c = new Client();
    await c.register('mp_user');
    const token = await c.token('/new');
    const other = await c.req('POST', '/login', { raw: multipart({ username: 'x', password: 'y', _csrf: token }) });
    assert.equal(other.status, 415);
    const garbage = await c.req('POST', '/new', { raw: { body: Buffer.from('garbage'), type: 'multipart/form-data; boundary=abc' } });
    assert.equal(garbage.status, 400);
    const noBoundary = await c.req('POST', '/new', { raw: { body: Buffer.from('x'), type: 'multipart/form-data' } });
    assert.equal(noBoundary.status, 400);
  });

  test('multipart forms are CSRF-protected too (no token, wrong token, foreign origin)', async () => {
    const c = new Client();
    await c.register('mp_csrf');
    const token = await c.token('/new');
    const noToken = await c.req('POST', '/new', { raw: multipart({ title: 'x', body: 'y' }, png()) });
    assert.equal(noToken.status, 403);
    const wrong = await c.req('POST', '/new', { raw: multipart({ title: 'x', body: 'y', _csrf: 'nope' }, png()) });
    assert.equal(wrong.status, 403);
    const foreign = await c.req('POST', '/new', { raw: multipart({ title: 'x', body: 'y', _csrf: token }, png()), origin: 'https://evil.example' });
    assert.equal(foreign.status, 403);
  });
});

describe('Likes and bookmarks', () => {
  let alice;
  let bob;
  let id;
  let draftId;
  const likes = (pid) => inst.db.prepare('SELECT COUNT(*) AS n FROM likes WHERE post_id = ?').get(pid).n;

  before(async () => {
    alice = new Client();
    bob = new Client();
    await alice.register('like_alice');
    await bob.register('like_bob');
    id = await alice.createPost('Likeable', 'content');
    draftId = await alice.createPost('Private', 'content', '');
  });

  test('liking toggles, counts once per user, and needs a login', async () => {
    assert.equal((await bob.submit(`/post/${id}`, `/post/${id}/like`, {})).status, 303);
    assert.equal(likes(id), 1);
    assert.equal((await bob.submit(`/post/${id}`, `/post/${id}/like`, {})).status, 303);
    assert.equal(likes(id), 0, 'second press removes the like');
    await bob.submit(`/post/${id}`, `/post/${id}/like`, {});
    await alice.submit(`/post/${id}`, `/post/${id}/like`, {});
    assert.equal(likes(id), 2);

    const anon = new Client();
    const token = await anon.token('/login');
    const r = await anon.post(`/post/${id}/like`, { _csrf: token });
    assert.equal(r.status, 303);
    assert.equal(r.location, '/login');
    assert.equal(likes(id), 2);
  });

  test('likes need a CSRF token, and drafts cannot be liked or bookmarked', async () => {
    assert.equal((await bob.post(`/post/${id}/like`, {})).status, 403);
    const t = await bob.token('/new');
    assert.equal((await bob.post(`/post/${draftId}/like`, { _csrf: t })).status, 404, 'foreign draft looks absent');
    assert.equal((await alice.post(`/post/${draftId}/bookmark`, { _csrf: await alice.token('/new') })).status, 403);
    assert.equal(likes(draftId), 0);
  });

  test('bookmarks are private to each user', async () => {
    await bob.submit(`/post/${id}`, `/post/${id}/bookmark`, {});
    assert.ok((await bob.get('/bookmarks')).text.includes('Likeable'));
    assert.ok(!(await alice.get('/bookmarks')).text.includes('Likeable'));
    assert.equal((await new Client().get('/bookmarks')).status, 303);
  });
});

describe('Search, tags and profiles', () => {
  let c;
  before(async () => {
    c = new Client();
    await c.register('search_user');
    assert.equal((await c.submit('/new', '/new', { title: 'Zebra crossing notes', body: 'plain body', published: '1', tags: 'Node JS, security' })).status, 303);
    assert.equal((await c.submit('/new', '/new', { title: 'Hidden draft zebra', body: 'nobody sees', published: '', tags: 'security' })).status, 303);
  });

  test('search finds published articles by title and by tag, never drafts', async () => {
    const byTitle = await new Client().get('/search?q=zebra');
    assert.equal(byTitle.status, 200);
    assert.ok(byTitle.text.includes('Zebra crossing notes'));
    assert.ok(!byTitle.text.includes('Hidden draft zebra'));
    assert.ok((await new Client().get('/search?q=%23node-js'.replace('%23', ''))).text.includes('Zebra crossing notes'));
  });

  test('search input is escaped and cannot inject SQL or LIKE wildcards', async () => {
    const xss = await new Client().get(`/search?q=${encodeURIComponent('<script>alert(1)</script>')}`);
    assert.equal(xss.status, 200);
    assert.ok(!/<script[\s>]/i.test(clean(xss.text)));
    assert.ok(xss.text.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    for (const q of ["' OR 1=1 --", "'; DROP TABLE posts; --", '%', '_', '\\']) {
      const r = await new Client().get(`/search?q=${encodeURIComponent(q)}`);
      assert.equal(r.status, 200, q);
      assert.ok(!r.text.includes('Zebra crossing notes'), `wildcard/injection "${q}" matched everything`);
    }
    assert.ok(inst.db.prepare('SELECT COUNT(*) AS n FROM posts').get().n > 0, 'posts table must still exist');
  });

  test('tags are normalised, strictly validated and limited', async () => {
    assert.ok((await new Client().get('/tag/node-js')).text.includes('Zebra crossing notes'));
    assert.ok((await new Client().get('/tag/security')).text.includes('Zebra crossing notes'));
    assert.ok(!(await new Client().get('/tag/security')).text.includes('Hidden draft zebra'));
    assert.equal((await new Client().get('/tag/nope')).status, 404);
    for (const p of ['/tag/%3Cscript%3E', '/tag/a'.padEnd(40, 'a'), '/tag/UPPER', '/tag/a_b']) assert.equal((await new Client().get(p)).status, 404, p);

    const bad = await c.submit('/new', '/new', { title: 't', body: 'b', tags: '<script>alert(1)</script>' });
    assert.equal(bad.status, 422);
    assert.ok(bad.text.includes('Tags can only contain'));
    assert.ok(!/<script[\s>]/i.test(clean(bad.text)));
    const many = await c.submit('/new', '/new', { title: 't', body: 'b', tags: 'a,b,c,d,e,f' });
    assert.equal(many.status, 422);
  });

  test('profiles show only published work and reject odd usernames', async () => {
    const page = await new Client().get('/u/search_user');
    assert.equal(page.status, 200);
    assert.ok(page.text.includes('Zebra crossing notes'));
    assert.ok(!page.text.includes('Hidden draft zebra'));
    for (const p of ['/u/nobody_here_x', '/u/%3Cscript%3E', '/u/ab', '/u/a-b-c']) assert.equal((await new Client().get(p)).status, 404, p);
  });
});

describe('Security Lab', () => {
  test('the lab shows hostile input as inert text and reports it as neutralised', async () => {
    const c = new Client();
    const r = await c.submit('/lab', '/lab', { payload: '<script>alert(1)</script><img src=x onerror=alert(2)> [x](javascript:alert(3))' });
    assert.equal(r.status, 200);
    assert.ok(r.text.includes('Neutralised'));
    assert.ok(!/<script[\s>]/i.test(clean(r.text)));
    assert.deepEqual(dangerousTags(clean(r.text)), []);
    assert.ok(r.text.includes('&lt;script&gt;'));
  });

  test('the lab is CSRF-protected, and a forged request (no token) is blocked with 403', async () => {
    const c = new Client();
    await c.get('/lab');
    assert.equal((await c.post('/lab', { payload: 'x' })).status, 403);
    assert.equal((await c.post('/lab/forged-delete', { action: 'delete-everything' })).status, 403);
  });

  test('static assets are served from an allowlist with the right types', async () => {
    const c = new Client();
    assert.match((await c.get('/style.css')).headers.get('content-type'), /text\/css/);
    assert.match((await c.get('/app.js')).headers.get('content-type'), /text\/javascript/);
    assert.equal((await c.get('/favicon.svg')).headers.get('content-type'), 'image/svg+xml');
    assert.equal((await c.get('/app.js/../server.js')).status, 404);
  });
});
