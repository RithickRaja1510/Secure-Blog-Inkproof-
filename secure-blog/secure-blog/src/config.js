'use strict';
const path = require('node:path');

const secure = process.env.COOKIE_SECURE === '1' || process.env.NODE_ENV === 'production';

module.exports = {
  port: Number(process.env.PORT || 3000),
  host: process.env.HOST || '127.0.0.1',
  dbFile: process.env.DB_FILE || path.join(__dirname, '..', 'data', 'blog.db'),

  // Cookies: the __Host- prefix (only valid with Secure) pins the cookie to this exact host.
  secureCookies: secure,
  cookieName: secure ? '__Host-sid' : 'sid',

  // Session lifetime: idle timeout and hard cap.
  sessionIdleMs: 30 * 60 * 1000,
  sessionAbsoluteMs: 8 * 60 * 60 * 1000,

  // Input limits (characters) and request body cap (bytes).
  // coverBytes: largest accepted image. uploadBytes: largest multipart request (image + form text).
  limits: {
    title: 150, post: 20000, comment: 2000, bodyBytes: 64 * 1024,
    coverBytes: 1.5 * 1024 * 1024,
    uploadBytes: 1.5 * 1024 * 1024 + 96 * 1024,
  },

  // Where uploaded images are stored (default: next to the database file, never inside /public).
  uploadDir: process.env.UPLOAD_DIR || null,

  // Only set TRUST_PROXY=1 when running behind a reverse proxy you control.
  trustProxy: process.env.TRUST_PROXY === '1',

  // Rate limits: [max events, window in ms]
  rate: {
    global: [600, 60 * 1000], // requests per IP per minute
    register: [20, 60 * 60 * 1000], // sign-ups per IP per hour
    loginIp: [30, 15 * 60 * 1000], // failed logins per IP per 15 min
    loginUser: [5, 15 * 60 * 1000], // failed logins per IP+username per 15 min
    comment: [10, 60 * 1000], // comments per user per minute
    react: [60, 60 * 1000], // likes + bookmarks per user per minute
    search: [40, 60 * 1000], // searches per IP per minute
  },

  quiet: process.env.QUIET === '1',
};
