'use strict';
const { HttpError } = require('./errors');
const authz = require('./authz');
const views = require('./views');
const { MIME, sniffImage, NAME_RE } = require('./upload');
const { UPLOAD_CSP } = require('./headers');
const {
  cleanText, USERNAME_RE, checkPassword, hashPassword, verifyPassword, parseTags, TAG_RE,
} = require('./security');

const PER_PAGE = 8;

module.exports = function buildRoutes(app) {
  const { models: m, cfg, limiters, uploads } = app;
  const routes = [];
  const add = (method, re, handler) => routes.push({ method, re, handler });

  /* ---------- helpers ---------- */

  const idFrom = (s) => Number.parseInt(s, 10);
  const pageFrom = (ctx) => {
    const n = Number.parseInt(ctx.url.searchParams.get('page') ?? '1', 10);
    return Math.min(Math.max(Number.isFinite(n) ? n : 1, 1), 10000);
  };

  /** Validate a cover image: size limit, then the REAL type from the file's magic bytes. */
  function readCover(ctx) {
    const file = ctx.files.find((f) => f.field === 'cover');
    if (!file) return {};
    if (file.data.length > cfg.limits.coverBytes) return { error: 'That image is larger than 1.5 MB. Choose a smaller one.' };
    const ext = sniffImage(file.data);
    if (!ext) return { error: 'Only PNG, JPG, GIF or WebP images are accepted.' };
    return { ext, data: file.data };
  }

  function parsePostForm(ctx) {
    const form = ctx.form;
    const title = cleanText(form.get('title'), { min: 1, max: cfg.limits.title });
    const body = cleanText(form.get('body'), { min: 1, max: cfg.limits.post, multiline: true });
    const tagsText = String(form.get('tags') ?? '').slice(0, 200);
    const tagResult = parseTags(tagsText);
    const cover = readCover(ctx);
    const errors = {};
    if (title.error) errors.title = title.error;
    if (body.error) errors.body = body.error;
    if (tagResult.error) errors.tags = tagResult.error;
    if (cover.error) errors.cover = cover.error;
    // Whitelist of accepted fields: author_id, created_at, role... in the request are never read.
    const values = {
      title: title.value ?? String(form.get('title') ?? '').slice(0, cfg.limits.title),
      body: body.value ?? String(form.get('body') ?? '').slice(0, cfg.limits.post),
      published: form.get('published') === '1',
      tags: tagsText,
    };
    return {
      values, errors, ok: Object.keys(errors).length === 0,
      tags: tagResult.tags, cover, removeCover: form.get('remove_cover') === '1',
    };
  }

  /** Look up a post the current user may at least see; otherwise behave as if it does not exist. */
  function visiblePost(ctx, id) {
    const post = Number.isInteger(id) ? m.getPost(id) : undefined;
    if (!post || !authz.canViewPost(ctx.user, post)) throw new HttpError(404, 'Not found.');
    return post;
  }

  function deny(ctx, action, type, id) {
    m.audit(ctx.user && ctx.user.id, `denied:${action}`, type, id, ctx.ip);
    app.log('authz_denied', { action, type, id, user: ctx.user && ctx.user.id, ip: ctx.ip });
    throw new HttpError(403, 'You are not allowed to do that.');
  }

  const requireLogin = (ctx) => (ctx.user ? null : ctx.redirect('/login'));

  function commentRows(ctx, post) {
    return m.commentsForPost(post.id).map((c) => ({
      c,
      canEditC: authz.canEditComment(ctx.user, c),
      canDeleteC: authz.canDeleteComment(ctx.user, c, post),
    }));
  }

  function renderPost(ctx, status, post, extra = {}) {
    if (ctx.user) ctx.ensureSession();
    return ctx.page(status, post.title, views.postPage({
      ctx,
      post,
      tags: m.tagsForPost(post.id),
      comments: commentRows(ctx, post),
      likes: m.likeCount(post.id),
      liked: ctx.user ? m.hasLiked(post.id, ctx.user.id) : false,
      bookmarked: ctx.user ? m.hasBookmarked(post.id, ctx.user.id) : false,
      canEdit: authz.canEditPost(ctx.user, post),
      canDelete: authz.canDeletePost(ctx.user, post),
      canComment: authz.canCommentOn(ctx.user, post),
      ...extra,
    }));
  }

  /* ---------- public pages ---------- */

  add('GET', /^\/$/, (ctx) => {
    const page = pageFrom(ctx);
    const sort = ctx.url.searchParams.get('sort') === 'popular' ? 'popular' : 'latest';
    const total = m.countPublished();
    ctx.ensureSession();
    ctx.page(200, 'Home', views.home({
      ctx,
      posts: m.listPublished(PER_PAGE, (page - 1) * PER_PAGE, sort),
      page, sort,
      pages: Math.max(1, Math.ceil(total / PER_PAGE)),
      tags: m.topTags(14),
      stats: m.siteStats(),
    }), 'home');
  });

  add('GET', /^\/search$/, (ctx) => {
    if (!limiters.search.hit(ctx.ip)) throw new HttpError(429, 'Too many searches. Wait a moment and try again.');
    const raw = ctx.url.searchParams.get('q') ?? '';
    const q = cleanText(raw.slice(0, 200), { min: 0, max: 80 });
    const term = q.value ?? raw.slice(0, 80).trim();
    const tag = term.toLowerCase().replace(/\s+/g, '-');
    const posts = term ? m.searchPosts(term, TAG_RE.test(tag) ? tag : '') : [];
    ctx.ensureSession();
    ctx.page(200, term ? `Search: ${term}` : 'Search', views.searchPage({ ctx, q: term, posts, tooLong: !!q.error }));
  });

  add('GET', /^\/tag\/([a-z0-9-]{1,24})$/, (ctx, tag) => {
    const page = pageFrom(ctx);
    const total = m.countByTag(tag);
    if (total === 0) throw new HttpError(404, 'No articles use that tag yet.');
    ctx.ensureSession();
    ctx.page(200, `#${tag}`, views.tagPage({
      ctx, tag, page, pages: Math.max(1, Math.ceil(total / PER_PAGE)), total,
      posts: m.postsByTag(tag, PER_PAGE, (page - 1) * PER_PAGE),
    }));
  });

  add('GET', /^\/u\/([A-Za-z0-9_]{3,30})$/, (ctx, name) => {
    const profile = m.userByName(name);
    if (!profile) throw new HttpError(404, 'No writer has that name.');
    ctx.ensureSession();
    ctx.page(200, profile.username, views.profilePage({
      ctx,
      profile: { username: profile.username, role: profile.role, created_at: profile.created_at },
      posts: m.postsByAuthorPublic(profile.id),
      stats: m.userStats(profile.id),
    }));
  });

  add('GET', /^\/post\/(\d{1,9})$/, (ctx, rawId) => {
    renderPost(ctx, 200, visiblePost(ctx, idFrom(rawId)));
  });

  /** Uploaded images. Names are random and validated; the type comes from our own extension map. */
  add('GET', /^\/uploads\/([a-f0-9]{32}\.[a-z]{3,4})$/, (ctx, name) => {
    if (!NAME_RE.test(name)) throw new HttpError(404, 'Not found.');
    const owner = m.postByCover(name);
    // A draft's cover is visible only to the author and admins.
    if (!owner || (owner.published !== 1 && !(ctx.user && (ctx.user.id === owner.author_id || authz.isAdmin(ctx.user))))) {
      throw new HttpError(404, 'Not found.');
    }
    const data = uploads.read(name);
    if (!data) throw new HttpError(404, 'Not found.');
    const ext = name.split('.')[1];
    return ctx.send(200, data, MIME[ext], {
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': UPLOAD_CSP,
      'Cache-Control': owner.published === 1 ? 'public, max-age=86400, immutable' : 'private, max-age=600',
    });
  });

  /* ---------- registration / login / logout ---------- */

  add('GET', /^\/register$/, (ctx) => {
    if (ctx.user) return ctx.redirect('/dashboard');
    ctx.ensureSession();
    return ctx.page(200, 'Register', views.authForm({ ctx, mode: 'register' }));
  });

  add('POST', /^\/register$/, async (ctx) => {
    if (!limiters.register.hit(ctx.ip)) throw new HttpError(429, 'Too many sign-ups from your address. Try again later.');
    const usernameRaw = String(ctx.form.get('username') ?? '').trim();
    const password = ctx.form.get('password');
    const errors = {};
    if (!USERNAME_RE.test(usernameRaw)) errors.username = '3–30 characters: letters, digits and underscore only.';
    const pwError = checkPassword(password, usernameRaw);
    if (pwError) errors.password = pwError;

    if (Object.keys(errors).length === 0) {
      const id = m.createUser(usernameRaw, await hashPassword(password));
      if (id) {
        m.audit(id, 'register', 'user', id, ctx.ip);
        ctx.loginAs(id); // new session id after privilege change
        return ctx.redirect('/dashboard', 'Welcome! Your account has been created.');
      }
      errors.username = 'That username is already taken.';
    }
    return ctx.page(422, 'Register', views.authForm({ ctx, mode: 'register', values: { username: usernameRaw }, errors }));
  });

  add('GET', /^\/login$/, (ctx) => {
    if (ctx.user) return ctx.redirect('/dashboard');
    ctx.ensureSession();
    return ctx.page(200, 'Log in', views.authForm({ ctx, mode: 'login' }));
  });

  add('POST', /^\/login$/, async (ctx) => {
    const username = String(ctx.form.get('username') ?? '').trim().slice(0, 64);
    const password = String(ctx.form.get('password') ?? '').slice(0, 200);
    const ipKey = `ip:${ctx.ip}`;
    const userKey = `ipuser:${ctx.ip}:${username.toLowerCase()}`;
    if (!limiters.loginIp.allowed(ipKey) || !limiters.loginUser.allowed(userKey)) {
      m.audit(null, 'login_throttled', 'user', null, ctx.ip);
      throw new HttpError(429, 'Too many failed attempts. Please wait a few minutes and try again.');
    }

    const user = USERNAME_RE.test(username) ? m.userByName(username) : undefined;
    // Always run a hash comparison so response time does not reveal whether the user exists.
    const hash = user ? user.password_hash : await app.dummyHash;
    const ok = (await verifyPassword(password, hash)) && !!user;

    if (!ok) {
      limiters.loginIp.hit(ipKey);
      limiters.loginUser.hit(userKey);
      m.audit(user ? user.id : null, 'login_failed', 'user', user ? user.id : null, ctx.ip);
      return ctx.page(401, 'Log in', views.authForm({
        ctx, mode: 'login', values: { username }, errors: { form: 'Invalid username or password.' },
      }));
    }
    limiters.loginUser.clear(userKey);
    m.audit(user.id, 'login', 'user', user.id, ctx.ip);
    ctx.loginAs(user.id); // session fixation defence: fresh id after authentication
    return ctx.redirect('/dashboard', `Welcome back, ${user.username}.`);
  });

  add('POST', /^\/logout$/, (ctx) => {
    if (ctx.user) m.audit(ctx.user.id, 'logout', 'user', ctx.user.id, ctx.ip);
    ctx.logout();
    return ctx.redirect('/');
  });

  /* ---------- dashboard / bookmarks ---------- */

  add('GET', /^\/dashboard$/, (ctx) => {
    if (requireLogin(ctx)) return null;
    return ctx.page(200, 'My posts', views.dashboard({
      ctx, posts: m.postsByAuthor(ctx.user.id), stats: m.userStats(ctx.user.id),
    }));
  });

  add('GET', /^\/bookmarks$/, (ctx) => {
    if (requireLogin(ctx)) return null;
    return ctx.page(200, 'Saved', views.bookmarksPage({ ctx, posts: m.bookmarkedBy(ctx.user.id) }));
  });

  /* ---------- posts ---------- */

  const emptyValues = { title: '', body: '', published: true, tags: '' };

  add('GET', /^\/new$/, (ctx) => {
    if (requireLogin(ctx)) return null;
    return ctx.page(200, 'New post', views.postForm({
      ctx, heading: 'Write something', action: '/new', submitLabel: 'Save post', values: emptyValues, errors: {},
    }));
  });

  add('POST', /^\/new$/, (ctx) => {
    if (requireLogin(ctx)) return null;
    const input = parsePostForm(ctx);
    if (!input.ok) {
      return ctx.page(422, 'New post', views.postForm({
        ctx, heading: 'Write something', action: '/new', submitLabel: 'Save post', values: input.values, errors: input.errors,
      }));
    }
    let cover = null;
    try {
      if (input.cover.ext) cover = uploads.save(input.cover.data, input.cover.ext);
      // author is ALWAYS the logged-in user; any author_id sent by the client is ignored.
      const id = m.createPost(ctx.user.id, { ...input.values, cover, tags: input.tags });
      m.audit(ctx.user.id, 'post_create', 'post', id, ctx.ip);
      return ctx.redirect(`/post/${id}`, input.values.published ? 'Post published.' : 'Draft saved.');
    } catch (e) {
      if (cover) uploads.remove(cover);
      throw e;
    }
  });

  add('GET', /^\/post\/(\d{1,9})\/edit$/, (ctx, rawId) => {
    if (requireLogin(ctx)) return null;
    const post = visiblePost(ctx, idFrom(rawId));
    if (!authz.canEditPost(ctx.user, post)) deny(ctx, 'post_edit_form', 'post', post.id);
    return ctx.page(200, 'Edit post', views.postForm({
      ctx, heading: 'Edit post', action: `/post/${post.id}/edit`, submitLabel: 'Save changes', isEdit: true, cover: post.cover,
      values: { title: post.title, body: post.body, published: post.published === 1, tags: m.tagsForPost(post.id).join(', ') },
      errors: {},
    }));
  });

  add('POST', /^\/post\/(\d{1,9})\/edit$/, (ctx, rawId) => {
    if (requireLogin(ctx)) return null;
    const post = visiblePost(ctx, idFrom(rawId));
    if (!authz.canEditPost(ctx.user, post)) deny(ctx, 'post_edit', 'post', post.id);
    const input = parsePostForm(ctx);
    if (!input.ok) {
      return ctx.page(422, 'Edit post', views.postForm({
        ctx, heading: 'Edit post', action: `/post/${post.id}/edit`, submitLabel: 'Save changes', isEdit: true,
        cover: post.cover, values: input.values, errors: input.errors,
      }));
    }
    const old = post.cover;
    let cover = old;
    let fresh = null;
    if (input.cover.ext) {
      fresh = uploads.save(input.cover.data, input.cover.ext);
      cover = fresh;
    } else if (input.removeCover) {
      cover = null;
    }
    let changes;
    try {
      changes = m.updatePost(post.id, ctx.user, { ...input.values, cover, tags: input.tags });
    } catch (e) {
      if (fresh) uploads.remove(fresh);
      throw e;
    }
    if (changes !== 1) {
      if (fresh) uploads.remove(fresh);
      deny(ctx, 'post_edit', 'post', post.id);
    }
    if (old && cover !== old) uploads.remove(old);
    m.audit(ctx.user.id, 'post_update', 'post', post.id, ctx.ip);
    return ctx.redirect(`/post/${post.id}`, 'Post updated.');
  });

  add('POST', /^\/post\/(\d{1,9})\/delete$/, (ctx, rawId) => {
    if (requireLogin(ctx)) return null;
    const post = visiblePost(ctx, idFrom(rawId));
    if (!authz.canDeletePost(ctx.user, post)) deny(ctx, 'post_delete', 'post', post.id);
    if (m.deletePost(post.id, ctx.user) !== 1) deny(ctx, 'post_delete', 'post', post.id);
    if (post.cover) uploads.remove(post.cover);
    m.audit(ctx.user.id, 'post_delete', 'post', post.id, ctx.ip);
    return ctx.redirect('/dashboard', 'Post deleted.');
  });

  /* ---------- likes and bookmarks ---------- */

  function reaction(kind) {
    return (ctx, rawId) => {
      if (requireLogin(ctx)) return null;
      const post = visiblePost(ctx, idFrom(rawId));
      if (post.published !== 1) deny(ctx, `${kind}_draft`, 'post', post.id); // drafts are private
      if (!limiters.react.hit(`u:${ctx.user.id}`)) throw new HttpError(429, 'Slow down a little.');
      if (kind === 'like') m.toggleLike(post.id, ctx.user.id);
      else m.toggleBookmark(post.id, ctx.user.id);
      return ctx.redirect(`/post/${post.id}#react`);
    };
  }
  add('POST', /^\/post\/(\d{1,9})\/like$/, reaction('like'));
  add('POST', /^\/post\/(\d{1,9})\/bookmark$/, reaction('bookmark'));

  /* ---------- comments ---------- */

  add('POST', /^\/post\/(\d{1,9})\/comments$/, (ctx, rawId) => {
    if (requireLogin(ctx)) return null;
    const post = visiblePost(ctx, idFrom(rawId));
    if (!authz.canCommentOn(ctx.user, post)) deny(ctx, 'comment_create', 'post', post.id);
    if (!limiters.comment.hit(`u:${ctx.user.id}`)) throw new HttpError(429, 'You are commenting too fast. Please slow down.');

    const body = cleanText(ctx.form.get('body'), { min: 1, max: cfg.limits.comment, multiline: true });
    if (body.error) {
      return renderPost(ctx, 422, post, {
        commentError: body.error,
        commentValue: String(ctx.form.get('body') ?? '').slice(0, cfg.limits.comment),
      });
    }
    const id = m.createComment(post.id, ctx.user.id, body.value);
    m.audit(ctx.user.id, 'comment_create', 'comment', id, ctx.ip);
    return ctx.redirect(`/post/${post.id}#c${id}`, 'Comment added.');
  });

  /** Fetch a comment together with its post, hiding comments on posts the user cannot see. */
  function commentWithPost(ctx, id) {
    const comment = Number.isInteger(id) ? m.getComment(id) : undefined;
    if (!comment) throw new HttpError(404, 'Not found.');
    const post = visiblePost(ctx, comment.post_id);
    return { comment, post };
  }

  add('GET', /^\/comment\/(\d{1,9})\/edit$/, (ctx, rawId) => {
    if (requireLogin(ctx)) return null;
    const { comment } = commentWithPost(ctx, idFrom(rawId));
    if (!authz.canEditComment(ctx.user, comment)) deny(ctx, 'comment_edit_form', 'comment', comment.id);
    return ctx.page(200, 'Edit comment', views.commentEditForm({ ctx, comment, value: comment.body }));
  });

  add('POST', /^\/comment\/(\d{1,9})\/edit$/, (ctx, rawId) => {
    if (requireLogin(ctx)) return null;
    const { comment } = commentWithPost(ctx, idFrom(rawId));
    if (!authz.canEditComment(ctx.user, comment)) deny(ctx, 'comment_edit', 'comment', comment.id);
    const body = cleanText(ctx.form.get('body'), { min: 1, max: cfg.limits.comment, multiline: true });
    if (body.error) {
      return ctx.page(422, 'Edit comment', views.commentEditForm({
        ctx, comment, value: String(ctx.form.get('body') ?? '').slice(0, cfg.limits.comment), error: body.error,
      }));
    }
    if (m.updateComment(comment.id, ctx.user, body.value) !== 1) deny(ctx, 'comment_edit', 'comment', comment.id);
    m.audit(ctx.user.id, 'comment_update', 'comment', comment.id, ctx.ip);
    return ctx.redirect(`/post/${comment.post_id}#c${comment.id}`, 'Comment updated.');
  });

  add('POST', /^\/comment\/(\d{1,9})\/delete$/, (ctx, rawId) => {
    if (requireLogin(ctx)) return null;
    const { comment, post } = commentWithPost(ctx, idFrom(rawId));
    if (!authz.canDeleteComment(ctx.user, comment, post)) deny(ctx, 'comment_delete', 'comment', comment.id);
    if (m.deleteComment(comment.id, ctx.user) !== 1) deny(ctx, 'comment_delete', 'comment', comment.id);
    m.audit(ctx.user.id, 'comment_delete', 'comment', comment.id, ctx.ip);
    return ctx.redirect(`/post/${post.id}`, 'Comment deleted.');
  });

  /* ---------- security lab ---------- */

  add('GET', /^\/lab$/, (ctx) => {
    ctx.ensureSession();
    return ctx.page(200, 'Security Lab', views.labPage({ ctx, payload: '' }));
  });

  add('POST', /^\/lab$/, (ctx) => {
    if (!limiters.search.hit(ctx.ip)) throw new HttpError(429, 'Too many tries. Wait a moment.');
    const clean = cleanText(ctx.form.get('payload'), { min: 1, max: 2000, multiline: true });
    if (clean.error) {
      return ctx.page(422, 'Security Lab', views.labPage({
        ctx, payload: String(ctx.form.get('payload') ?? '').slice(0, 2000), error: clean.error,
      }));
    }
    return ctx.page(200, 'Security Lab', views.labPage({ ctx, payload: clean.value, run: true }));
  });

  /* ---------- admin ---------- */

  add('GET', /^\/admin\/audit$/, (ctx) => {
    if (requireLogin(ctx)) return null;
    if (!authz.isAdmin(ctx.user)) deny(ctx, 'admin_audit', 'page', null);
    return ctx.page(200, 'Audit log', views.auditPage({ ctx, rows: m.recentAudit(200) }));
  });

  return routes;
};
