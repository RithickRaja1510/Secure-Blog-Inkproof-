'use strict';
/**
 * Security primitives used across the app:
 *   1. Output encoding / safe templating          -> XSS
 *   2. Restricted markup renderer for post bodies -> XSS
 *   3. Password hashing, tokens, constant-time compare
 *   4. Input validation and rate limiting
 */
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);

/* ------------------------------------------------------------------ */
/* 1. Output encoding + auto-escaping template tag                     */
/* ------------------------------------------------------------------ */

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };

/** Encode a value for use in HTML text or a quoted attribute. */
function esc(value) {
  return String(value).replace(/[&<>"'`]/g, (c) => ESC[c]);
}

const TRUSTED = Symbol('trusted-html');

/** Mark a string as already-safe HTML. Use ONLY on output produced by this module. */
function raw(s) {
  const str = String(s);
  return { [TRUSTED]: str, toString: () => str };
}

function render(v) {
  if (v === null || v === undefined || v === false) return '';
  if (Array.isArray(v)) return v.map(render).join('');
  if (typeof v === 'object' && TRUSTED in v) return v[TRUSTED];
  return esc(v); // everything else, including user data, is encoded
}

/**
 * Tagged template: every ${interpolation} is HTML-escaped unless it is the result
 * of another html`` call (or raw()). Forgetting to escape is therefore impossible.
 */
function html(strings, ...values) {
  let out = '';
  strings.forEach((s, i) => {
    out += s;
    if (i < values.length) out += render(values[i]);
  });
  return raw(out);
}

/* ------------------------------------------------------------------ */
/* 2. Restricted markup: **bold**, *italic*, `code`, [text](http(s) url) */
/* ------------------------------------------------------------------ */

function safeUrl(candidate) {
  try {
    const u = new URL(candidate);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null; // blocks javascript:, data:, vbscript:
    if (u.username || u.password) return null; // blocks user:pass@evil.example phishing links
    return u.href;
  } catch {
    return null;
  }
}

// Text is escaped FIRST; the formatting tags are inserted afterwards, so user text can never add tags.
function formatText(text) {
  return esc(text)
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*\n]+)\*/g, '<em>$1</em>');
}

function renderInline(s) {
  const linkRe = /\[([^\]\n]{1,200})\]\((https?:\/\/[^\s)]{1,500})\)/gi;
  let out = '';
  let last = 0;
  let m;
  while ((m = linkRe.exec(s)) !== null) {
    out += formatText(s.slice(last, m.index));
    const href = safeUrl(m[2]);
    out += href
      ? `<a href="${esc(href)}" rel="nofollow noopener noreferrer" target="_blank">${formatText(m[1])}</a>`
      : formatText(m[0]);
    last = linkRe.lastIndex;
  }
  return out + formatText(s.slice(last));
}

/** Render a post body (restricted markup) to safe HTML paragraphs. */
function renderBody(text) {
  const paras = String(text)
    .replace(/\r\n?/g, '\n')
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter(Boolean);
  return raw(paras.map((p) => `<p>${renderInline(p).replace(/\n/g, '<br>')}</p>`).join('\n'));
}

/** Render a comment: plain text only (no links, no formatting), line breaks preserved. */
function renderPlain(text) {
  return raw(`<p>${esc(text).replace(/\n/g, '<br>')}</p>`);
}

/* ------------------------------------------------------------------ */
/* 3. Passwords and tokens                                             */
/* ------------------------------------------------------------------ */

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024 });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$');
}

async function verifyPassword(password, stored) {
  const [scheme, N, r, p, saltB64, keyB64] = String(stored).split('$');
  if (scheme !== 'scrypt') return false;
  const expected = Buffer.from(keyB64, 'base64');
  const key = await scrypt(password, Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024,
  });
  return crypto.timingSafeEqual(key, expected);
}

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest();

/** Constant-time string comparison (hashing first hides length differences). */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

function parseCookies(header) {
  const out = Object.create(null);
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* 4. Validation and rate limiting                                     */
/* ------------------------------------------------------------------ */

// Control characters (except \n and \t in multiline fields) and bidi-override characters
// (used for text-spoofing) are removed.
const CONTROL_MULTI = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F‪-‮⁦-⁩]/g;
const CONTROL_SINGLE = /[\u0000-\u001F\u007F‪-‮⁦-⁩]/g;

function cleanText(value, { min = 0, max, multiline = false }) {
  if (typeof value !== 'string') return { error: 'This field is required.' };
  const v = value
    .replace(/\r\n?/g, '\n')
    .normalize('NFC')
    .replace(multiline ? CONTROL_MULTI : CONTROL_SINGLE, '')
    .trim();
  if (v.length < min) return { error: min === 1 ? 'This field is required.' : `Must be at least ${min} characters.` };
  if (v.length > max) return { error: `Must be at most ${max} characters.` };
  return { value: v };
}

const USERNAME_RE = /^[A-Za-z0-9_]{3,30}$/;

function checkPassword(password, username) {
  if (typeof password !== 'string') return 'Password is required.';
  if (password.length < 10) return 'Password must be at least 10 characters.';
  if (password.length > 128) return 'Password must be at most 128 characters.';
  if (username && password.toLowerCase() === username.toLowerCase()) return 'Password must not equal the username.';
  return null;
}

/** Fixed-window counter keyed by an arbitrary string. */
class Limiter {
  constructor([max, windowMs]) {
    this.max = max;
    this.windowMs = windowMs;
    this.entries = new Map();
    this.timer = setInterval(() => this.sweep(), 60 * 1000);
    this.timer.unref();
  }
  _entry(key) {
    const now = Date.now();
    let e = this.entries.get(key);
    if (!e || e.reset <= now) {
      e = { count: 0, reset: now + this.windowMs };
      this.entries.set(key, e);
    }
    return e;
  }
  /** Count an event; returns false once the limit is exceeded. */
  hit(key) {
    const e = this._entry(key);
    e.count += 1;
    return e.count <= this.max;
  }
  /** Is another event currently allowed? (does not count) */
  allowed(key) {
    return this._entry(key).count < this.max;
  }
  clear(key) {
    this.entries.delete(key);
  }
  sweep() {
    const now = Date.now();
    for (const [k, e] of this.entries) if (e.reset <= now) this.entries.delete(k);
  }
}

/* ------------------------------------------------------------------ */
/* 5. Content helpers (tags, search, excerpts, output inspection)      */
/* ------------------------------------------------------------------ */

const readingMinutes = (text) => Math.max(1, Math.round(String(text).split(/\s+/).filter(Boolean).length / 200));

/** Stable small number derived from a string (used to pick avatar colours / cover art). */
function hueIndex(str, n) {
  let h = 0;
  for (const ch of String(str)) h = (h * 31 + ch.codePointAt(0)) >>> 0;
  return h % n;
}

const TAG_RE = /^[a-z0-9][a-z0-9-]{0,23}$/;

/** "Node JS, security" -> ['node-js', 'security'] (strict allowlist, max 5). */
function parseTags(input) {
  if (typeof input !== 'string' || input.trim() === '') return { tags: [] };
  const parts = input
    .split(',')
    .map((s) => s.normalize('NFC').trim().toLowerCase().replace(/\s+/g, '-'))
    .filter(Boolean);
  const tags = [...new Set(parts)];
  if (tags.length > 5) return { tags: [], error: 'Use at most 5 tags.' };
  if (!tags.every((t) => TAG_RE.test(t))) {
    return { tags: [], error: 'Tags can only contain letters, digits and dashes (up to 24 characters each).' };
  }
  return { tags };
}

/** Escape LIKE wildcards so a search for "%" or "_" matches literally. */
const likeEscape = (s) => String(s).replace(/[\\%_]/g, '\\$&');

/** Plain-text preview of a post body (markup symbols removed; the view still escapes it). */
function plainExcerpt(body, max = 180) {
  const t = String(body)
    .replace(/\[([^\]\n]*)\]\([^)\s]*\)/g, '$1')
    .replace(/[*`]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const lastSpace = cut.lastIndexOf(' ');
  return `${(lastSpace > max * 0.6 ? cut.slice(0, lastSpace) : cut).trimEnd()}…`;
}

/** Real HTML start tags (quote-aware, so text inside an attribute value is not mistaken for a tag). */
const startTags = (markup) => String(markup).match(/<[a-zA-Z](?:"[^"]*"|'[^']*'|[^>"'])*>/g) || [];
/** The same tag with every quoted attribute value emptied: what is left is real attribute syntax. */
const bareTag = (tag) => tag.replace(/"[^"]*"|'[^']*'/g, '""');

/** Count dangerous constructs in generated HTML (used by the Security Lab page and tests). */
function inspectMarkup(markup) {
  const tags = startTags(markup);
  return {
    tags: tags.length,
    scripts: tags.filter((t) => /^<script\b/i.test(t)).length,
    handlers: tags.filter((t) => /\son[a-z]+\s*=/i.test(bareTag(t))).length,
    jsUrls: tags.filter((t) => /(href|src|action)\s*=\s*["']?\s*javascript:/i.test(t)).length,
  };
}

module.exports = {
  readingMinutes, hueIndex, parseTags, likeEscape, plainExcerpt, inspectMarkup, TAG_RE,
  esc, raw, html, renderBody, renderPlain, safeUrl,
  hashPassword, verifyPassword, randomToken, sha256, safeEqual, parseCookies,
  cleanText, USERNAME_RE, checkPassword, Limiter,
};
