'use strict';

// Scripts may only come from our own /app.js (no inline scripts, no inline event handlers, no eval).
// Styles only from /style.css. Nothing can be loaded from, or sent to, another site.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' blob:", // blob: is only used for the cover-image preview before upload
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join('; ');

// Served with every uploaded image: even if a file were somehow HTML, the browser would not run it.
const UPLOAD_CSP = "default-src 'none'; sandbox";

function applySecurityHeaders(res, cfg) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  // NOT 'no-referrer': with that policy browsers send "Origin: null" on same-site form posts,
  // which our CSRF origin check (correctly) rejects. 'same-origin' still leaks nothing cross-site.
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  if (cfg.secureCookies) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
}

module.exports = { CSP, UPLOAD_CSP, applySecurityHeaders };
