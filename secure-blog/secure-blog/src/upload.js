'use strict';
/**
 * Secure file uploads (cover images) without third-party code.
 *
 *  - multipart/form-data is parsed by hand with hard limits (size, number of parts, header size)
 *  - the client's file name and Content-Type are IGNORED; the type is decided from the file's magic bytes
 *  - only PNG, JPEG, GIF and WebP are accepted (no SVG/HTML: those can carry script)
 *  - stored under a random 128-bit name in a directory outside the web root; served only through
 *    /uploads/<name> with a fixed Content-Type, nosniff and a sandboxing CSP
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { HttpError } = require('./errors');

const NAME_RE = /^[a-f0-9]{32}\.(?:png|jpg|gif|webp)$/;
const MIME = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** Decide the real image type from the first bytes; returns 'png' | 'jpg' | 'gif' | 'webp' | null. */
function sniffImage(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  if (buf.subarray(0, 8).equals(PNG_MAGIC)) return 'png';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpg';
  const head6 = buf.toString('latin1', 0, 6);
  if (head6 === 'GIF87a' || head6 === 'GIF89a') return 'gif';
  if (buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  return null;
}

const bad = () => new HttpError(400, 'The upload could not be read. Please try again.');

/** Minimal, strict multipart/form-data parser. Returns text fields and file parts. */
function parseMultipart(buf, contentType, { maxParts = 12, maxTextBytes = 64 * 1024 } = {}) {
  const m = /boundary=(?:"([^"]{1,70})"|([^;\s]{1,70}))/i.exec(contentType || '');
  const boundary = m && (m[1] || m[2]);
  if (!boundary || !/^[0-9A-Za-z'()+_,\-./:=? ]{1,70}$/.test(boundary)) throw bad();

  const delim = Buffer.from(`--${boundary}`);
  const sep = Buffer.from(`\r\n--${boundary}`);
  if (buf.indexOf(delim) !== 0) throw bad(); // no preamble tolerated

  const fields = new URLSearchParams();
  const files = [];
  let pos = delim.length;
  let parts = 0;
  let textBytes = 0;

  for (;;) {
    if (buf[pos] === 0x2d && buf[pos + 1] === 0x2d) break; // closing "--"
    if (buf[pos] !== 0x0d || buf[pos + 1] !== 0x0a) throw bad();
    pos += 2;
    if (++parts > maxParts) throw bad();

    const headEnd = buf.indexOf('\r\n\r\n', pos);
    if (headEnd < 0 || headEnd - pos > 2048) throw bad();
    const head = buf.toString('latin1', pos, headEnd);
    const next = buf.indexOf(sep, headEnd + 4);
    if (next < 0) throw bad();
    const data = buf.subarray(headEnd + 4, next);

    const cd = /^content-disposition:\s*form-data;([^\r\n]*)$/im.exec(head);
    const name = cd && /\bname="([^"\r\n]{1,64})"/i.exec(cd[1]);
    if (!name) throw bad();
    const filename = /\bfilename="([^"\r\n]*)"/i.exec(cd[1]);

    if (filename) {
      // An empty file input (no file chosen) arrives as filename="" with no bytes: ignore it.
      if (filename[1] !== '' || data.length > 0) files.push({ field: name[1], data: Buffer.from(data) });
    } else {
      textBytes += data.length;
      if (textBytes > maxTextBytes) throw bad();
      fields.append(name[1], data.toString('utf8'));
    }
    pos = next + sep.length;
  }
  if (files.length > 1) throw bad();
  return { fields, files };
}

/** Disk store with random names. Names are validated on every access (no path traversal). */
function createUploadStore(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return {
    dir,
    save(buf, ext) {
      const name = `${crypto.randomBytes(16).toString('hex')}.${ext}`;
      fs.writeFileSync(path.join(dir, name), buf, { flag: 'wx', mode: 0o644 });
      return name;
    },
    read(name) {
      if (typeof name !== 'string' || !NAME_RE.test(name)) return null;
      try {
        return fs.readFileSync(path.join(dir, name));
      } catch {
        return null;
      }
    },
    remove(name) {
      if (typeof name !== 'string' || !NAME_RE.test(name)) return;
      try {
        fs.unlinkSync(path.join(dir, name));
      } catch {
        /* already gone */
      }
    },
  };
}

module.exports = { sniffImage, parseMultipart, createUploadStore, NAME_RE, MIME };
