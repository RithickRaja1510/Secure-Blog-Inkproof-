'use strict';
/**
 * Data access. Every query is a prepared statement with bound parameters (no string
 * concatenation of user input), which rules out SQL injection.
 *
 * Authorization is enforced HERE as well as in the route handlers: update/delete
 * statements carry the ownership condition in their WHERE clause, so even a handler
 * that forgot a check could not modify someone else's content.
 */
const now = () => new Date().toISOString();
const isAdmin = (u) => (u && u.role === 'admin' ? 1 : 0);

// Columns every article card needs (constant text, no user input).
const CARD = `SELECT p.id, p.title, p.body, p.cover, p.created_at, u.username AS author,
    (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likes,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments,
    (SELECT GROUP_CONCAT(t.tag, ',') FROM post_tags t WHERE t.post_id = p.id) AS tags
  FROM posts p JOIN users u ON u.id = p.author_id`;
const BY_NEW = 'ORDER BY p.created_at DESC, p.id DESC';

module.exports = function createModels(db) {
  const st = {
    insUser: db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'),
    userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
    userById: db.prepare('SELECT id, username, role, created_at FROM users WHERE id = ?'),

    listLatest: db.prepare(`${CARD} WHERE p.published = 1 ${BY_NEW} LIMIT ? OFFSET ?`),
    listPopular: db.prepare(`${CARD} WHERE p.published = 1 ORDER BY likes DESC, p.created_at DESC, p.id DESC LIMIT ? OFFSET ?`),
    countPublished: db.prepare('SELECT COUNT(*) AS n FROM posts WHERE published = 1'),
    byTag: db.prepare(
      `${CARD} WHERE p.published = 1 AND EXISTS (SELECT 1 FROM post_tags t WHERE t.post_id = p.id AND t.tag = ?) ${BY_NEW} LIMIT ? OFFSET ?`),
    countByTag: db.prepare(
      'SELECT COUNT(*) AS n FROM posts p WHERE p.published = 1 AND EXISTS (SELECT 1 FROM post_tags t WHERE t.post_id = p.id AND t.tag = ?)'),
    search: db.prepare(
      `${CARD} WHERE p.published = 1 AND (p.title LIKE ? ESCAPE '\\' OR p.body LIKE ? ESCAPE '\\'
         OR EXISTS (SELECT 1 FROM post_tags t WHERE t.post_id = p.id AND t.tag = ?)) ${BY_NEW} LIMIT 30`),
    byAuthorPublic: db.prepare(`${CARD} WHERE p.published = 1 AND p.author_id = ? ${BY_NEW}`),
    bookmarked: db.prepare(
      `${CARD} JOIN bookmarks b ON b.post_id = p.id WHERE b.user_id = ? AND p.published = 1 ORDER BY b.created_at DESC`),
    mine: db.prepare(
      `SELECT p.id, p.title, p.published, p.cover, p.created_at, p.updated_at,
         (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likes,
         (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments
       FROM posts p WHERE p.author_id = ? ORDER BY p.id DESC`),
    topTags: db.prepare(
      `SELECT t.tag, COUNT(*) AS n FROM post_tags t JOIN posts p ON p.id = t.post_id
        WHERE p.published = 1 GROUP BY t.tag ORDER BY n DESC, t.tag ASC LIMIT ?`),
    tagsForPost: db.prepare('SELECT tag FROM post_tags WHERE post_id = ? ORDER BY tag'),
    delTags: db.prepare('DELETE FROM post_tags WHERE post_id = ?'),
    insTag: db.prepare('INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)'),

    getPost: db.prepare('SELECT p.*, u.username AS author FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = ?'),
    postByCover: db.prepare('SELECT id, author_id, published FROM posts WHERE cover = ?'),
    insPost: db.prepare('INSERT INTO posts (author_id, title, body, published, cover, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'),
    updPost: db.prepare(
      'UPDATE posts SET title = ?, body = ?, published = ?, cover = ?, updated_at = ? WHERE id = ? AND (author_id = ? OR ? = 1)'),
    delPost: db.prepare('DELETE FROM posts WHERE id = ? AND (author_id = ? OR ? = 1)'),

    commentsForPost: db.prepare(
      `SELECT c.*, u.username AS author FROM comments c JOIN users u ON u.id = c.author_id
        WHERE c.post_id = ? ORDER BY c.id ASC`),
    getComment: db.prepare('SELECT * FROM comments WHERE id = ?'),
    insComment: db.prepare('INSERT INTO comments (post_id, author_id, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'),
    // Only the author may change the words of a comment (not even admins or the post owner).
    updComment: db.prepare('UPDATE comments SET body = ?, updated_at = ? WHERE id = ? AND author_id = ?'),
    // Delete: comment author, owner of the post (moderation) or admin.
    delComment: db.prepare(
      `DELETE FROM comments WHERE id = ?
         AND (author_id = ? OR ? = 1 OR post_id IN (SELECT id FROM posts WHERE author_id = ?))`),

    countLikes: db.prepare('SELECT COUNT(*) AS n FROM likes WHERE post_id = ?'),
    hasLike: db.prepare('SELECT 1 AS x FROM likes WHERE post_id = ? AND user_id = ?'),
    insLike: db.prepare('INSERT INTO likes (post_id, user_id, created_at) VALUES (?, ?, ?)'),
    delLike: db.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?'),
    hasMark: db.prepare('SELECT 1 AS x FROM bookmarks WHERE post_id = ? AND user_id = ?'),
    insMark: db.prepare('INSERT INTO bookmarks (post_id, user_id, created_at) VALUES (?, ?, ?)'),
    delMark: db.prepare('DELETE FROM bookmarks WHERE post_id = ? AND user_id = ?'),

    stPosts: db.prepare('SELECT COUNT(*) AS n FROM posts WHERE published = 1'),
    stUsers: db.prepare('SELECT COUNT(*) AS n FROM users'),
    stBlocked: db.prepare(
      `SELECT COUNT(*) AS n FROM audit_log
        WHERE action LIKE 'denied:%' OR action LIKE 'csrf_blocked%' OR action = 'login_throttled'`),
    uPosts: db.prepare('SELECT COUNT(*) AS n FROM posts WHERE author_id = ? AND published = 1'),
    uLikes: db.prepare('SELECT COUNT(*) AS n FROM likes l JOIN posts p ON p.id = l.post_id WHERE p.author_id = ?'),
    uComments: db.prepare('SELECT COUNT(*) AS n FROM comments c JOIN posts p ON p.id = c.post_id WHERE p.author_id = ?'),

    audit: db.prepare('INSERT INTO audit_log (ts, user_id, action, target_type, target_id, ip) VALUES (?, ?, ?, ?, ?, ?)'),
    recentAudit: db.prepare(
      `SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT ?`),
  };

  function inTransaction(fn) {
    db.exec('BEGIN');
    try {
      const result = fn();
      db.exec('COMMIT');
      return result;
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }

  const toggle = (has, ins, del) => (postId, userId) => {
    if (Number(del.run(postId, userId).changes) > 0) return false;
    try {
      ins.run(postId, userId, now());
    } catch (e) {
      if (!/UNIQUE|PRIMARY/i.test(String(e.message))) throw e; // concurrent double-click: already on
    }
    return true;
  };

  return {
    createUser(username, passwordHash, role = 'user') {
      try {
        return Number(st.insUser.run(username, passwordHash, role, now()).lastInsertRowid);
      } catch (e) {
        if (/UNIQUE/i.test(String(e.message))) return null; // username taken
        throw e;
      }
    },
    userByName: (name) => st.userByName.get(name),
    userById: (id) => st.userById.get(id),

    listPublished: (limit, offset, sort = 'latest') => (sort === 'popular' ? st.listPopular : st.listLatest).all(limit, offset),
    countPublished: () => st.countPublished.get().n,
    postsByTag: (tag, limit, offset) => st.byTag.all(tag, limit, offset),
    countByTag: (tag) => st.countByTag.get(tag).n,
    searchPosts: (q, tag) => {
      const like = `%${q.replace(/[\\%_]/g, '\\$&')}%`;
      return st.search.all(like, like, tag);
    },
    postsByAuthorPublic: (uid) => st.byAuthorPublic.all(uid),
    bookmarkedBy: (uid) => st.bookmarked.all(uid),
    postsByAuthor: (uid) => st.mine.all(uid),
    topTags: (limit = 12) => st.topTags.all(limit),
    tagsForPost: (id) => st.tagsForPost.all(id).map((r) => r.tag),

    getPost: (id) => st.getPost.get(id),
    postByCover: (name) => st.postByCover.get(name),
    createPost: (uid, { title, body, published, cover = null, tags = [] }) =>
      inTransaction(() => {
        const t = now();
        const id = Number(st.insPost.run(uid, title, body, published ? 1 : 0, cover, t, t).lastInsertRowid);
        for (const tag of tags) st.insTag.run(id, tag);
        return id;
      }),
    updatePost: (id, actor, { title, body, published, cover = null, tags = [] }) => {
      db.exec('BEGIN');
      try {
        const changes = Number(st.updPost.run(title, body, published ? 1 : 0, cover, now(), id, actor.id, isAdmin(actor)).changes);
        if (changes === 1) {
          st.delTags.run(id);
          for (const tag of tags) st.insTag.run(id, tag);
        }
        db.exec(changes === 1 ? 'COMMIT' : 'ROLLBACK');
        return changes;
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
    },
    deletePost: (id, actor) => Number(st.delPost.run(id, actor.id, isAdmin(actor)).changes),

    commentsForPost: (postId) => st.commentsForPost.all(postId),
    getComment: (id) => st.getComment.get(id),
    createComment: (postId, uid, body) => {
      const t = now();
      return Number(st.insComment.run(postId, uid, body, t, t).lastInsertRowid);
    },
    updateComment: (id, actor, body) => Number(st.updComment.run(body, now(), id, actor.id).changes),
    deleteComment: (id, actor) => Number(st.delComment.run(id, actor.id, isAdmin(actor), actor.id).changes),

    likeCount: (postId) => st.countLikes.get(postId).n,
    hasLiked: (postId, uid) => !!st.hasLike.get(postId, uid),
    toggleLike: toggle(st.hasLike, st.insLike, st.delLike),
    hasBookmarked: (postId, uid) => !!st.hasMark.get(postId, uid),
    toggleBookmark: toggle(st.hasMark, st.insMark, st.delMark),

    siteStats: () => ({
      posts: st.stPosts.get().n,
      users: st.stUsers.get().n,
      blocked: st.stBlocked.get().n,
    }),
    userStats: (uid) => ({
      posts: st.uPosts.get(uid).n,
      likes: st.uLikes.get(uid).n,
      comments: st.uComments.get(uid).n,
    }),

    audit: (userId, action, targetType, targetId, ip) =>
      void st.audit.run(now(), userId ?? null, action, targetType ?? null, targetId ?? null, ip ?? null),
    recentAudit: (limit = 100) => st.recentAudit.all(limit),
  };
};
