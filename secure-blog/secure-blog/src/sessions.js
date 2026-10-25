'use strict';
const { randomToken, sha256 } = require('./security');

const hashId = (sid) => sha256(sid).toString('hex');

/**
 * Server-side sessions. The cookie carries only a random 256-bit id; the CSRF token lives
 * server-side next to it (synchronizer-token pattern).
 */
module.exports = function createSessionStore(db, cfg) {
  const ins = db.prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, flash, created_at, last_seen) VALUES (?, ?, ?, NULL, ?, ?)');
  const sel = db.prepare('SELECT * FROM sessions WHERE id_hash = ?');
  const touch = db.prepare('UPDATE sessions SET last_seen = ? WHERE id_hash = ?');
  const del = db.prepare('DELETE FROM sessions WHERE id_hash = ?');
  const purge = db.prepare('DELETE FROM sessions WHERE last_seen < ? OR created_at < ?');
  const setFlash = db.prepare('UPDATE sessions SET flash = ? WHERE id_hash = ?');
  const getFlash = db.prepare('SELECT flash FROM sessions WHERE id_hash = ?');

  const timer = setInterval(() => {
    const t = Date.now();
    purge.run(t - cfg.sessionIdleMs, t - cfg.sessionAbsoluteMs);
  }, 5 * 60 * 1000);
  timer.unref();

  return {
    /** Create a session; returns the raw id (for the cookie) and the stored row. */
    create(userId = null) {
      const sid = randomToken(32);
      const t = Date.now();
      ins.run(hashId(sid), userId, randomToken(32), t, t);
      return { sid, session: sel.get(hashId(sid)) };
    },
    load(sid) {
      if (typeof sid !== 'string' || sid.length < 20 || sid.length > 128) return null;
      const row = sel.get(hashId(sid));
      if (!row) return null;
      const t = Date.now();
      if (t - row.last_seen > cfg.sessionIdleMs || t - row.created_at > cfg.sessionAbsoluteMs) {
        del.run(row.id_hash);
        return null;
      }
      touch.run(t, row.id_hash);
      return row;
    },
    destroy(sid) {
      if (typeof sid === 'string') del.run(hashId(sid));
    },
    setFlash: (idHash, msg) => void setFlash.run(msg, idHash),
    takeFlash(idHash) {
      const row = getFlash.get(idHash);
      if (row && row.flash) setFlash.run(null, idHash);
      return row ? row.flash : null;
    },
  };
};
