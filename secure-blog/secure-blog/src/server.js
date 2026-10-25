'use strict';
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const baseConfig = require('./config');
const { openDatabase } = require('./db');
const createModels = require('./models');
const createSessionStore = require('./sessions');
const buildRoutes = require('./routes');
const views = require('./views');
const { HttpError } = require('./errors');
const { Limiter, parseCookies, safeEqual, hashPassword } = require('./security');
const { applySecurityHeaders } = require('./headers');
const { parseMultipart, createUploadStore } = require('./upload');

/* ------------------------------------------------------------------ */
/* Request context                                                     */
/* ------------------------------------------------------------------ */

function clientIp(req, cfg) {
  if (cfg.trustProxy) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (xff.length) return xff[xff.length - 1]; // the address our own proxy appended
  }
  return req.socket.remoteAddress || 'unknown';
}

const UPLOAD_ROUTE = /^\/(?:new|post\/\d{1,9}\/edit)$/;

class Context {
  constructor(req, res, app, url) {
    this.req = req;
    this.res = res;
    this.app = app;
    this.url = url;
    this.ip = clientIp(req, app.cfg);
    this.session = null;
    this.sid = null;
    this.user = null;
    this.form = null;
    this.files = [];
    this.setCookies = [];
  }

  /* ----- sessions ----- */
  loadSession() {
    const sid = parseCookies(this.req.headers.cookie)[this.app.cfg.cookieName];
    const session = this.app.store.load(sid);
    if (!session) return;
    this.sid = sid;
    this.session = session;
    if (session.user_id) {
      this.user = this.app.models.userById(session.user_id) || null;
      if (!this.user) {
        this.app.store.destroy(sid);
        this.session = null;
        this.sid = null;
      }
    }
  }
  _issue(userId) {
    const { sid, session } = this.app.store.create(userId);
    this.sid = sid;
    this.session = session;
    const { cfg } = this.app;
    this.setCookies.push(
      `${cfg.cookieName}=${sid}; Path=/; HttpOnly; SameSite=Strict${cfg.secureCookies ? '; Secure' : ''}`,
    );
  }
  ensureSession() {
    if (!this.session) this._issue(null);
  }
  loginAs(userId) {
    if (this.sid) this.app.store.destroy(this.sid); // never keep the pre-login id
    this._issue(userId);
    this.user = this.app.models.userById(userId);
  }
  logout() {
    if (this.sid) this.app.store.destroy(this.sid);
    const { cfg } = this.app;
    this.setCookies.push(
      `${cfg.cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${cfg.secureCookies ? '; Secure' : ''}`,
    );
    this.session = null;
    this.sid = null;
    this.user = null;
  }
  takeFlash() {
    return this.session ? this.app.store.takeFlash(this.session.id_hash) : null;
  }

  /* ----- request checks (CSRF) ----- */

  /** Read the request body into a Buffer, never accepting more than `max` bytes. */
  readBuffer(max) {
    return new Promise((resolve, reject) => {
      const tooBig = () => {
        this.res.setHeader('Connection', 'close'); // stop the client from streaming the rest
        return new HttpError(413, 'Request body too large.');
      };
      if (Number(this.req.headers['content-length']) > max) return reject(tooBig());
      const chunks = [];
      let size = 0;
      let rejected = false;
      this.req.on('data', (c) => {
        size += c.length;
        if (size > max) {
          if (!rejected) {
            rejected = true;
            reject(tooBig());
          }
          return;
        }
        chunks.push(c);
      });
      this.req.on('end', () => {
        if (!rejected) resolve(Buffer.concat(chunks));
      });
      this.req.on('error', reject);
      return undefined;
    });
  }

  /**
   * Read a form body. urlencoded everywhere; multipart/form-data (with the larger size cap)
   * ONLY on the two routes that accept a cover image.
   */
  async readForm() {
    const contentType = String(this.req.headers['content-type'] || '');
    const type = contentType.split(';')[0].trim().toLowerCase();
    const { limits } = this.app.cfg;
    if (type === 'multipart/form-data' && UPLOAD_ROUTE.test(this.url.pathname)) {
      const { fields, files } = parseMultipart(await this.readBuffer(limits.uploadBytes), contentType);
      this.form = fields;
      this.files = files;
      return;
    }
    if (type !== 'application/x-www-form-urlencoded') throw new HttpError(415, 'Unsupported content type.');
    this.form = new URLSearchParams((await this.readBuffer(limits.bodyBytes)).toString('utf8'));
  }

  /**
   * CSRF defence layer 1: the request must come from our own origin.
   * (Layer 2 is the per-session synchronizer token; layer 3 is the SameSite=Strict cookie.)
   */
  checkOrigin() {
    const { origin, referer, host } = this.req.headers;
    let source = origin;
    if (origin === 'null') source = null; // sandboxed iframes, cross-origin redirects
    else if (!origin) source = referer;
    let sourceHost = null;
    try {
      sourceHost = source ? new URL(source).host : null;
    } catch {
      sourceHost = null;
    }
    if (!sourceHost || sourceHost !== host) this.blockCsrf('origin');
  }

  checkCsrfToken() {
    const expected = this.session && this.session.csrf_token;
    const supplied = this.form.get('_csrf');
    if (!expected || !safeEqual(String(supplied ?? ''), expected)) this.blockCsrf('token');
  }

  blockCsrf(reason) {
    this.app.models.audit(this.user && this.user.id, `csrf_blocked:${reason}`, null, null, this.ip);
    this.app.log('csrf_blocked', { reason, path: this.url.pathname, ip: this.ip });
    throw new HttpError(403, 'Request blocked: it did not come from this site (possible cross-site request forgery). Reload the page and try again.');
  }

  /* ----- responses ----- */
  send(status, body, type = 'text/html; charset=utf-8', headers = {}) {
    const buf = Buffer.from(body);
    if (this.setCookies.length) this.res.setHeader('Set-Cookie', this.setCookies);
    this.res.writeHead(status, {
      'Content-Type': type,
      'Content-Length': buf.length,
      'Cache-Control': 'no-store', // pages contain CSRF tokens and personal data
      ...headers,
    });
    this.res.end(buf);
  }
  page(status, title, content, bodyClass = '') {
    this.send(status, String(views.layout(this, { title, content, bodyClass })));
  }
  redirect(location, flash) {
    if (!location.startsWith('/') || location.startsWith('//')) throw new Error('redirect target must be a local path');
    if (flash && this.session) this.app.store.setFlash(this.session.id_hash, flash);
    this.send(303, '', 'text/plain; charset=utf-8', { Location: location });
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Application                                                         */
/* ------------------------------------------------------------------ */

function createApp(overrides = {}) {
  const cfg = {
    ...baseConfig,
    ...overrides,
    rate: { ...baseConfig.rate, ...(overrides.rate || {}) },
    limits: { ...baseConfig.limits, ...(overrides.limits || {}) },
  };
  const db = openDatabase(cfg.dbFile);
  const models = createModels(db);
  const store = createSessionStore(db, cfg);
  const log = cfg.quiet ? () => {} : (event, data) => console.log(JSON.stringify({ t: new Date().toISOString(), event, ...data }));
  const limiters = {
    global: new Limiter(cfg.rate.global),
    register: new Limiter(cfg.rate.register),
    loginIp: new Limiter(cfg.rate.loginIp),
    loginUser: new Limiter(cfg.rate.loginUser),
    comment: new Limiter(cfg.rate.comment),
    react: new Limiter(cfg.rate.react),
    search: new Limiter(cfg.rate.search),
  };
  const uploadDir = cfg.uploadDir
    || (cfg.dbFile === ':memory:' ? fs.mkdtempSync(path.join(os.tmpdir(), 'inkproof-uploads-')) : path.join(path.dirname(cfg.dbFile), 'uploads'));
  const uploads = createUploadStore(uploadDir);
  const app = { cfg, db, models, store, limiters, uploads, log, dummyHash: hashPassword('placeholder-for-timing-equalisation') };
  const routes = buildRoutes(app);
  // Static assets come from a fixed in-memory allowlist: no user-controlled file paths.
  const asset = (file, type) => ({ type, data: fs.readFileSync(path.join(__dirname, '..', 'public', file)) });
  const assets = new Map([
    ['/style.css', asset('style.css', 'text/css; charset=utf-8')],
    ['/app.js', asset('app.js', 'text/javascript; charset=utf-8')],
    ['/favicon.svg', asset('favicon.svg', 'image/svg+xml')],
  ]);

  async function handle(req, res) {
    applySecurityHeaders(res, cfg);
    let ctx;
    try {
      if ((req.url || '').length > 2048) throw new HttpError(414, 'URL too long.');
      const url = new URL(req.url, 'http://localhost');
      ctx = new Context(req, res, app, url);

      if (!limiters.global.hit(ctx.ip)) throw new HttpError(429, 'Too many requests.');
      if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'POST') {
        res.setHeader('Allow', 'GET, HEAD, POST');
        throw new HttpError(405, 'Method not allowed.');
      }

      const staticFile = req.method !== 'POST' && assets.get(url.pathname);
      if (staticFile) {
        res.writeHead(200, { 'Content-Type': staticFile.type, 'Content-Length': staticFile.data.length, 'Cache-Control': 'public, max-age=300' });
        return res.end(staticFile.data);
      }

      ctx.loadSession();

      if (req.method === 'POST') {
        ctx.checkOrigin(); // every state-changing request must pass both CSRF checks...
        await ctx.readForm();
        ctx.checkCsrfToken(); // ...before any route code runs
      }

      const wantMethod = req.method === 'HEAD' ? 'GET' : req.method;
      let pathMatched = false;
      for (const r of routes) {
        const match = r.re.exec(url.pathname);
        if (!match) continue;
        pathMatched = true;
        if (r.method !== wantMethod) continue;
        await r.handler(ctx, ...match.slice(1));
        return undefined;
      }
      throw new HttpError(pathMatched ? 405 : 404, pathMatched ? 'Method not allowed.' : 'Page not found.');
    } catch (err) {
      return sendError(ctx, req, res, err);
    }
  }

  function sendError(ctx, req, res, err) {
    const status = err instanceof HttpError ? err.status : 500;
    if (!(err instanceof HttpError)) log('server_error', { message: String(err && err.message), stack: String(err && err.stack) });
    // Never leak internals: unexpected errors get a generic message.
    const message = err instanceof HttpError ? err.message : 'Something went wrong on our side.';
    if (res.headersSent) return res.end();
    try {
      if (ctx) return ctx.page(status, String(status), views.errorPage({ status, message }));
    } catch {
      /* fall through to plain text */
    }
    res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(`${status} ${message}`);
  }

  const server = http.createServer(handle);
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 50;
  // Raised by Node's HTTP parser before any of our code runs (malformed or oversized request).
  // Log the cause and answer with a readable message instead of an empty 400.
  server.on('clientError', (err, socket) => {
    log('client_error', { code: err.code, message: String(err.message).slice(0, 200) });
    if (!socket.writable) return socket.destroy();
    const tooLarge = err.code === 'HPE_HEADER_OVERFLOW';
    const status = tooLarge ? '431 Request Header Fields Too Large' : '400 Bad Request';
    const body = tooLarge
      ? 'Request headers too large. Usually this means big cookies from other apps on 127.0.0.1/localhost. Open the site in a private/incognito window, or clear cookies for this address.'
      : `Bad request (${err.code || 'parse error'}). Make sure you use http:// (not https://) and try a private/incognito window.`;
    return socket.end(
      `HTTP/1.1 ${status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
    );
  });

  return {
    app, server, db, models,
    listen: (port = cfg.port, host = cfg.host) => new Promise((resolve) => server.listen(port, host, () => resolve(server.address()))),
    close: () => new Promise((resolve) => { server.close(() => { db.close(); resolve(); }); server.closeAllConnections(); }),
  };
}

module.exports = { createApp };

if (require.main === module) {
  const instance = createApp();
  instance.listen().then((addr) => {
    console.log(`Inkproof listening on http://${addr.address}:${addr.port}`);
    if (!instance.app.cfg.secureCookies) console.log('Note: running without HTTPS. Set COOKIE_SECURE=1 and serve behind TLS in production.');
  });
}
