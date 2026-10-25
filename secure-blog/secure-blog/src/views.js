'use strict';
/**
 * HTML views. Everything goes through the auto-escaping html`` tag from security.js,
 * so user-controlled values are encoded unless explicitly passed through renderBody()/renderPlain().
 * There is no inline <script>, no inline style and no inline event handler anywhere (CSP forbids them);
 * behaviour lives in /app.js, appearance in /style.css.
 */
const {
  html, raw, renderBody, renderPlain, plainExcerpt, readingMinutes, hueIndex, inspectMarkup,
} = require('./security');
const { CSP } = require('./headers');

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function dateParts(iso) {
  const d = new Date(iso);
  return { day: d.getUTCDate(), mon: MONTHS[d.getUTCMonth()], year: d.getUTCFullYear() };
}
const fmt = (iso) => {
  const p = dateParts(iso);
  return `${p.day} ${p.mon} ${p.year}`;
};
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const splitTags = (s) => (s ? String(s).split(',').filter(Boolean) : []);

const ICONS = {
  heart: '<path d="M12 20.5s-7.8-4.7-9.7-9.6C1 7.500 2.900 4 6.500 4c2 0 3.700 1.100 5.500 3.200C13.800 5.100 15.500 4 17.500 4 21.100 4 23 7.500 21.700 10.900c-1.900 4.900-9.700 9.600-9.700 9.600z"/>',
  chat: '<path d="M4 5h16a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1h-8l-5 4v-4H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z"/>',
  bookmark: '<path d="M6 3h12v18l-6-4.500L6 21z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.500 2"/>',
  search: '<circle cx="10.500" cy="10.500" r="6.500"/><path d="M15.500 15.500L21 21"/>',
  pen: '<path d="M4 20l1-4L16.500 4.500a2.100 2.100 0 0 1 3 3L8 19z"/><path d="M14 7l3 3"/>',
  flask: '<path d="M9 3h6M10 3v6L4.500 18.500A2 2 0 0 0 6.200 21.500h11.600a2 2 0 0 0 1.700-3L14 9V3"/><path d="M7.500 15h9"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.800"/><path d="M4 18l5-5 4 4 3-3 4 4"/>',
  shield: '<path d="M12 3l8 3v6c0 4.500-3.200 7.800-8 9-4.800-1.200-8-4.500-8-9V6z"/><path d="M8.500 12l2.500 2.500L15.500 10"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  edit: '<path d="M4 20l1-4L16.500 4.500a2.100 2.100 0 0 1 3 3L8 19z"/>',
};
const ic = (name, cls = '') =>
  raw(`<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.200" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`);

const csrfField = (ctx) => html`<input type="hidden" name="_csrf" value="${ctx.session.csrf_token}">`;
const errorText = (errors, field) => (errors && errors[field] ? html`<p class="field-error" role="alert">${errors[field]}</p>` : '');

const avatar = (name, size = '') =>
  html`<span class="av av-${hueIndex(name, 6)} ${size}" aria-hidden="true">${[...String(name)][0].toUpperCase()}</span>`;

const chip = (t) => html`<a class="chip" href="/tag/${t}">#${t}</a>`;

/** Circular cancellation mark: author name around the rim, date in the middle. */
function postmark(id, who, iso) {
  const d = dateParts(iso);
  return html`<svg class="postmark" viewBox="0 0 120 120" aria-hidden="true">
  <defs><path id="pm${id}" d="M60 60m-45 0a45 45 0 1 1 90 0a45 45 0 1 1-90 0"/></defs>
  <circle class="pm-ring" cx="60" cy="60" r="56"/>
  <circle class="pm-ring" cx="60" cy="60" r="33"/>
  <text class="pm-arc" textLength="268" lengthAdjust="spacing"><textPath href="#pm${id}">${String(who).slice(0, 14)} • inkproof •</textPath></text>
  <text class="pm-day" x="60" y="58" text-anchor="middle">${d.day}</text>
  <text class="pm-mon" x="60" y="76" text-anchor="middle">${d.mon}</text>
</svg>`;
}

const wordmark = html`<span class="wordmark"><svg class="logo" viewBox="0 0 32 32" aria-hidden="true"><path class="logo-shield" d="M16 2l12 4v9c0 7-5 12-12 15C9 27 4 22 4 15V6z"/><path class="logo-tick" d="M10.500 16l4 4 7.500-8"/></svg><span>Inkproof</span></span>`;

/* ------------------------------------------------------------------ */
/* Layout                                                              */
/* ------------------------------------------------------------------ */

function layout(ctx, { title, content, bodyClass = '' }) {
  const flash = ctx.takeFlash();
  const user = ctx.user;
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>${title} | Inkproof</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script>
</head>
<body class="${bodyClass}">
<a class="skip" href="#main">Skip to content</a>
<header class="top">
  <a class="brand" href="/" aria-label="Inkproof home">${wordmark}</a>
  <form class="hsearch" action="/search" method="get" role="search">
    <input name="q" type="search" maxlength="80" placeholder="Search articles" aria-label="Search articles" autocomplete="off">
    <button class="ico-btn" type="submit" aria-label="Search">${ic('search')}</button>
  </form>
  <nav class="nav" aria-label="Main">
    <a href="/lab">${ic('flask')}Security Lab</a>
    ${user
      ? html`${user.role === 'admin' ? html`<a href="/admin/audit">${ic('shield')}Audit log</a>` : ''}
    <a href="/bookmarks">${ic('bookmark')}Saved</a>
    <a class="btn small" href="/new">${ic('pen')}Write</a>
    <a class="me" href="/dashboard" title="Your posts">${avatar(user.username, 'sm')}<span>${user.username}</span></a>
    <form method="post" action="/logout" class="inline">${csrfField(ctx)}<button class="linkbtn" type="submit">Log out</button></form>`
      : html`<a href="/login">Log in</a>
    <a class="btn small" href="/register">Join</a>`}
  </nav>
</header>
<main id="main">
${flash ? html`<p class="flash" role="status">${flash}</p>` : ''}
${content}
</main>
<footer class="foot">
  <p class="foot-mark" aria-hidden="true">Inkproof</p>
  <p>Built for a Secure Software Engineering mini project. It stops XSS, CSRF and edits that are not yours.</p>
</footer>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* Cards and grids                                                     */
/* ------------------------------------------------------------------ */

function card(p, i = 0, featured = false) {
  const tags = splitTags(p.tags);
  return html`<article class="stamp-wrap tilt-${i % 4} ${featured ? 'feature' : ''}">
  <div class="stamp">
    <a class="cover-link" href="/post/${p.id}" tabindex="-1" aria-hidden="true">
      ${p.cover
        ? html`<img class="cover" src="/uploads/${p.cover}" alt="" loading="lazy">`
        : html`<div class="cover art art-${hueIndex(String(p.id), 8)}"></div>`}
    </a>
    ${postmark(p.id, p.author, p.created_at)}
    <div class="stamp-body">
      <h2 class="stamp-title"><a href="/post/${p.id}">${p.title}</a></h2>
      <p class="excerpt">${plainExcerpt(p.body, featured ? 260 : 150)}</p>
      ${tags.length ? html`<div class="chips">${tags.slice(0, 3).map(chip)}</div>` : ''}
      <div class="stamp-foot">
        <a class="by" href="/u/${p.author}">${avatar(p.author, 'sm')}<span>${p.author}</span></a>
        <span class="stat" title="Likes">${ic('heart')}${p.likes}</span>
        <span class="stat" title="Comments">${ic('chat')}${p.comments}</span>
        <span class="stat" title="Reading time">${ic('clock')}${readingMinutes(p.body)} min</span>
      </div>
    </div>
  </div>
</article>`;
}

const grid = (posts, { feature = false } = {}) =>
  html`<div class="grid">${posts.map((p, i) => card(p, i, feature && i === 0))}</div>`;

const empty = (title, text, action) => html`<div class="empty">
  <p class="empty-title">${title}</p>
  <p>${text}</p>
  ${action || ''}
</div>`;

function pager(base, page, pages) {
  if (pages <= 1) return '';
  const join = base.includes('?') ? '&' : '?';
  return html`<nav class="pager" aria-label="Pages">
  ${page > 1 ? html`<a class="btn ghost" href="${base}${join}page=${page - 1}">Newer</a>` : html`<span></span>`}
  <span>Page ${page} of ${pages}</span>
  ${page < pages ? html`<a class="btn ghost" href="${base}${join}page=${page + 1}">Older</a>` : html`<span></span>`}
</nav>`;
}

/* ------------------------------------------------------------------ */
/* Home                                                                */
/* ------------------------------------------------------------------ */

function home({ ctx, posts, page, pages, sort, tags, stats }) {
  const base = sort === 'popular' ? '/?sort=popular' : '/';
  return html`<section class="hero">
  <div class="hero-copy">
    <h1 class="hero-title">Write loud.<br>Nothing gets in.</h1>
    <p class="hero-sub">A blog where every post and comment is treated as hostile until proven harmless, and you can watch it happen.</p>
    <div class="hero-actions">
      <a class="btn big" href="${ctx.user ? '/new' : '/register'}">${ctx.user ? 'Write an article' : 'Start writing'}</a>
      <a class="btn big ghost" href="/lab">Try to break it</a>
    </div>
    <p class="hero-stats">${plural(stats.posts, 'article')} from ${plural(stats.users, 'writer')}. ${plural(stats.blocked, 'blocked request')} so far.</p>
  </div>
  <div class="deck" id="deck">
    <div class="deck-card">
      <p class="deck-who">Someone just posted:</p>
      <code class="payload" id="deck-payload">&lt;script&gt;alert(1)&lt;/script&gt;</code>
      <p class="deck-out"><span id="deck-out">Shown as plain text. Nothing ran.</span></p>
    </div>
    <div class="slap" id="deck-slap">Neutralised</div>
  </div>
</section>

${tags.length ? html`<nav class="tagcloud" aria-label="Popular tags">${tags.map((t) => html`<a class="chip big-chip" href="/tag/${t.tag}">#${t.tag}<b>${t.n}</b></a>`)}</nav>` : ''}

<section class="feed">
  <div class="feed-head">
    <h2>Fresh off the press</h2>
    <nav class="seg" aria-label="Sort">
      <a href="/" class="${sort === 'latest' ? 'on' : ''}" ${sort === 'latest' ? raw('aria-current="true"') : ''}>Latest</a>
      <a href="/?sort=popular" class="${sort === 'popular' ? 'on' : ''}" ${sort === 'popular' ? raw('aria-current="true"') : ''}>Most liked</a>
    </nav>
  </div>
  ${posts.length
    ? grid(posts, { feature: page === 1 })
    : empty('Nothing here yet', 'Be the first to publish an article.', html`<a class="btn" href="${ctx.user ? '/new' : '/register'}">Write the first one</a>`)}
  ${pager(base, page, pages)}
</section>`;
}

function searchPage({ ctx, q, posts, tooLong }) {
  return html`<section class="page-head">
  <h1>${q ? html`Results for “${q}”` : 'Search'}</h1>
  <form class="bigsearch" action="/search" method="get" role="search">
    <input name="q" type="search" maxlength="80" value="${q}" placeholder="Title, text or #tag" aria-label="Search articles" autocomplete="off">
    <button class="btn" type="submit">Search</button>
  </form>
  ${tooLong ? html`<p class="field-error">Searches are limited to 80 characters.</p>` : ''}
</section>
${q
    ? (posts.length
      ? html`${grid(posts)}<p class="muted center">${plural(posts.length, 'article')} found.</p>`
      : empty('No matches', 'Try a shorter word, or browse the tags on the home page.', html`<a class="btn ghost" href="/">Back home</a>`))
    : empty('What are you looking for?', 'Search article titles, text and tags.')}`;
}

function tagPage({ tag, posts, page, pages, total }) {
  return html`<section class="page-head">
  <h1>#${tag}</h1>
  <p class="muted">${plural(total, 'article')} with this tag.</p>
</section>
${grid(posts)}
${pager(`/tag/${tag}`, page, pages)}`;
}

function profilePage({ ctx, profile, posts, stats }) {
  return html`<section class="profile">
  ${avatar(profile.username, 'xl')}
  <div>
    <h1>${profile.username}${profile.role === 'admin' ? html` <span class="badge">Admin</span>` : ''}</h1>
    <p class="muted">Writing here since ${fmt(profile.created_at)}</p>
    <ul class="statrow">
      <li><b>${stats.posts}</b> ${stats.posts === 1 ? 'article' : 'articles'}</li>
      <li><b>${stats.likes}</b> ${stats.likes === 1 ? 'like' : 'likes'} received</li>
      <li><b>${stats.comments}</b> ${stats.comments === 1 ? 'comment' : 'comments'} received</li>
    </ul>
  </div>
</section>
${posts.length ? grid(posts) : empty('No published articles yet', 'When this writer publishes something, it will show up here.')}`;
}

function bookmarksPage({ posts }) {
  return html`<section class="page-head"><h1>Saved for later</h1></section>
${posts.length
    ? grid(posts)
    : empty('Nothing saved yet', 'Open an article and press Save to keep it here.', html`<a class="btn ghost" href="/">Browse articles</a>`)}`;
}

/* ------------------------------------------------------------------ */
/* Article                                                             */
/* ------------------------------------------------------------------ */

function postPage({
  ctx, post, tags, comments, likes, liked, bookmarked, canEdit, canDelete, canComment, commentError, commentValue,
}) {
  const login = '/login';
  return html`<div class="progress" aria-hidden="true"></div>
<article class="post">
  <header class="post-head">
    <div class="chips">${tags.map(chip)}${post.published ? '' : html`<span class="stampmark draft">Draft</span>`}</div>
    <h1 class="post-title">${post.title}</h1>
    <p class="byline">
      <a class="by" href="/u/${post.author}">${avatar(post.author)}<span>${post.author}</span></a>
      <span>${fmt(post.created_at)}</span>
      ${post.updated_at !== post.created_at ? html`<span>Updated ${fmt(post.updated_at)}</span>` : ''}
      <span>${ic('clock')}${readingMinutes(post.body)} min read</span>
    </p>
  </header>
  ${post.cover
    ? html`<figure class="post-cover"><img src="/uploads/${post.cover}" alt="Cover image for ${post.title}"></figure>`
    : html`<div class="post-cover art art-${hueIndex(String(post.id), 8)}" aria-hidden="true"></div>`}
  <div class="prose">${renderBody(post.body)}</div>

  <div class="reactbar" id="react">
    ${post.published
    ? html`${ctx.user
      ? html`<form method="post" action="/post/${post.id}/like" class="inline">${csrfField(ctx)}
        <button class="react ${liked ? 'on' : ''}" type="submit" aria-pressed="${liked ? 'true' : 'false'}">${ic('heart')}<span>${likes}</span><span class="sr">${liked ? 'Unlike' : 'Like'}</span></button></form>
      <form method="post" action="/post/${post.id}/bookmark" class="inline">${csrfField(ctx)}
        <button class="react ${bookmarked ? 'on' : ''}" type="submit" aria-pressed="${bookmarked ? 'true' : 'false'}">${ic('bookmark')}<span>${bookmarked ? 'Saved' : 'Save'}</span></button></form>`
      : html`<a class="react" href="${login}" title="Log in to like">${ic('heart')}<span>${likes}</span></a>
      <a class="react" href="${login}" title="Log in to save">${ic('bookmark')}<span>Save</span></a>`}`
    : ''}
    ${canEdit ? html`<a class="react" href="/post/${post.id}/edit">${ic('edit')}<span>Edit</span></a>` : ''}
    ${canDelete ? html`<form method="post" action="/post/${post.id}/delete" class="inline" data-confirm="Delete this article and all its comments?">${csrfField(ctx)}<button class="react danger" type="submit">${ic('trash')}<span>Delete</span></button></form>` : ''}
  </div>
</article>

<section class="comments" id="comments">
  <h2>${comments.length === 0 ? 'Comments' : plural(comments.length, 'comment')}</h2>
  ${comments.length === 0 && post.published ? html`<p class="muted">No comments yet. Say something kind, or something sharp.</p>` : ''}
  <ol class="thread">
  ${comments.map(({ c, canEditC, canDeleteC }, i) => html`<li class="comment ${i % 2 ? 'alt' : ''}" id="c${c.id}">
    ${avatar(c.author)}
    <div class="bubble">
      <p class="meta"><a href="/u/${c.author}">${c.author}</a><span>${fmt(c.created_at)}${c.updated_at !== c.created_at ? ', edited' : ''}</span></p>
      <div class="comment-text">${renderPlain(c.body)}</div>
      ${canEditC || canDeleteC ? html`<div class="row-actions">
        ${canEditC ? html`<a href="/comment/${c.id}/edit">Edit</a>` : ''}
        ${canDeleteC ? html`<form method="post" action="/comment/${c.id}/delete" class="inline" data-confirm="Delete this comment?">${csrfField(ctx)}<button class="linkbtn" type="submit">Delete</button></form>` : ''}
      </div>` : ''}
    </div>
  </li>`)}
  </ol>

  ${canComment
    ? html`<form method="post" action="/post/${post.id}/comments" class="form comment-form">
    ${csrfField(ctx)}
    <label for="comment-body">Add a comment</label>
    <textarea id="comment-body" name="body" rows="4" maxlength="2000" required data-count="2000">${commentValue || ''}</textarea>
    <p class="counter" data-counter-for="comment-body">0 / 2000</p>
    ${errorText(commentError ? { body: commentError } : null, 'body')}
    <button class="btn" type="submit">Post comment</button>
  </form>`
    : (ctx.user ? '' : html`<p class="muted">${raw('<a href="/login">Log in</a>')} or ${raw('<a href="/register">join</a>')} to comment.</p>`)}
</section>`;
}

/* ------------------------------------------------------------------ */
/* Forms                                                               */
/* ------------------------------------------------------------------ */

function postForm({ ctx, heading, action, values, errors, submitLabel, isEdit = false, cover = null }) {
  return html`<section class="editor">
  <h1>${heading}</h1>
  <form method="post" action="${action}" enctype="multipart/form-data" class="form wide">
    ${csrfField(ctx)}
    <label for="title">Title</label>
    <input id="title" name="title" type="text" maxlength="150" required value="${values.title}" data-count="150">
    <p class="counter" data-counter-for="title">0 / 150</p>
    ${errorText(errors, 'title')}

    <label for="cover">Cover image <span class="muted">(optional)</span></label>
    ${isEdit && cover ? html`<div class="current-cover"><img src="/uploads/${cover}" alt="Current cover image">
      <label class="check"><input type="checkbox" name="remove_cover" value="1"> Remove this cover</label></div>` : ''}
    <label class="drop" for="cover">
      <input id="cover" name="cover" type="file" accept="image/png,image/jpeg,image/gif,image/webp" data-preview="cover-preview" data-max="1572864">
      <span class="drop-text">${ic('image')}<span>Choose an image or drop it here<small>PNG, JPG, GIF or WebP, up to 1.5 MB</small></span></span>
      <img id="cover-preview" class="drop-preview" alt="Selected cover preview" hidden>
    </label>
    <p class="field-error" id="cover-error" role="alert" hidden></p>
    ${errorText(errors, 'cover')}

    <label for="body">Article</label>
    <textarea id="body" name="body" rows="16" maxlength="20000" required data-count="20000">${values.body}</textarea>
    <p class="counter" data-counter-for="body">0 / 20000</p>
    ${errorText(errors, 'body')}

    <label for="tags">Tags <span class="muted">(up to 5, separated by commas)</span></label>
    <input id="tags" name="tags" type="text" maxlength="200" placeholder="security, nodejs, notes" value="${values.tags}">
    ${errorText(errors, 'tags')}

    <label class="check"><input type="checkbox" name="published" value="1" ${values.published ? 'checked' : ''}> Publish now. Leave unticked to keep it as a private draft.</label>
    <button class="btn big" type="submit">${submitLabel}</button>
  </form>
  <aside class="cheat">
    <h2>Formatting</h2>
    <p>Only a few things are allowed, on purpose.</p>
    <ul>
      <li><code>**bold**</code> for <strong>bold</strong></li>
      <li><code>*italic*</code> for <em>italic</em></li>
      <li><code>\`code\`</code> for <code>code</code></li>
      <li><code>[text](https://site.com)</code> for links</li>
      <li>A blank line starts a new paragraph</li>
    </ul>
    <p>HTML is shown as plain text, and <code>javascript:</code> links never become links.</p>
  </aside>
</section>`;
}

function commentEditForm({ ctx, comment, value, error }) {
  return html`<section class="editor narrow">
  <h1>Edit comment</h1>
  <form method="post" action="/comment/${comment.id}/edit" class="form">
    ${csrfField(ctx)}
    <label for="comment-edit">Your comment</label>
    <textarea id="comment-edit" name="body" rows="6" maxlength="2000" required data-count="2000">${value}</textarea>
    <p class="counter" data-counter-for="comment-edit">0 / 2000</p>
    ${errorText(error ? { body: error } : null, 'body')}
    <div class="row-actions">
      <button class="btn" type="submit">Save comment</button>
      <a class="btn ghost" href="/post/${comment.post_id}#c${comment.id}">Cancel</a>
    </div>
  </form>
</section>`;
}

function authForm({ ctx, mode, values = {}, errors = {} }) {
  const login = mode === 'login';
  return html`<section class="auth">
  <div class="auth-side">
    <h1>${login ? 'Welcome back' : 'Join the vault'}</h1>
    <ul class="proofs">
      <li>${ic('shield')}<span>Passwords are salted and hashed. Nobody can read yours, including us.</span></li>
      <li>${ic('shield')}<span>Every form carries a secret token, so other sites cannot act as you.</span></li>
      <li>${ic('shield')}<span>Only you can edit or delete your own articles and comments.</span></li>
    </ul>
  </div>
  <form method="post" action="/${mode}" class="form card-form">
    ${csrfField(ctx)}
    ${errors.form ? html`<p class="field-error" role="alert">${errors.form}</p>` : ''}
    <label for="username">Username</label>
    <input id="username" name="username" type="text" maxlength="30" required autocomplete="username" value="${values.username || ''}">
    ${errorText(errors, 'username')}

    <label for="password">Password ${login ? '' : html`<span class="muted">(10 to 128 characters)</span>`}</label>
    <input id="password" name="password" type="password" maxlength="128" required autocomplete="${login ? 'current-password' : 'new-password'}">
    ${login ? '' : html`<div class="meter" data-meter-for="password" aria-hidden="true"><i></i><i></i><i></i><i></i></div>`}
    ${errorText(errors, 'password')}

    <button class="btn big" type="submit">${login ? 'Log in' : 'Create account'}</button>
    <p class="muted">${login ? html`New here? <a href="/register">Create an account</a>.` : html`Already have one? <a href="/login">Log in</a>.`}</p>
  </form>
</section>`;
}

/* ------------------------------------------------------------------ */
/* Dashboard, audit, errors                                            */
/* ------------------------------------------------------------------ */

function dashboard({ ctx, posts, stats }) {
  return html`<section class="page-head">
  <h1>Hello, ${ctx.user.username}</h1>
  <ul class="statrow">
    <li><b>${stats.posts}</b> published</li>
    <li><b>${stats.likes}</b> ${stats.likes === 1 ? 'like' : 'likes'}</li>
    <li><b>${stats.comments}</b> ${stats.comments === 1 ? 'comment' : 'comments'}</li>
  </ul>
  <p><a class="btn" href="/new">${ic('pen')}Write a new post</a></p>
</section>
${posts.length === 0
    ? empty('Your desk is empty', 'Write your first article. It takes a minute.', html`<a class="btn" href="/new">Start writing</a>`)
    : html`<ul class="rows">
  ${posts.map((p) => html`<li class="row">
    <span class="row-art ${p.cover ? '' : html`art art-${hueIndex(String(p.id), 8)}`}">${p.cover ? html`<img src="/uploads/${p.cover}" alt="">` : ''}</span>
    <div class="row-main">
      <a class="row-title" href="/post/${p.id}">${p.title}</a>
      <p class="muted">Updated ${fmt(p.updated_at)}, ${plural(p.likes, 'like')}, ${plural(p.comments, 'comment')}</p>
    </div>
    <span class="stampmark ${p.published ? 'live' : 'draft'}">${p.published ? 'Published' : 'Draft'}</span>
    <div class="row-actions">
      <a href="/post/${p.id}/edit">Edit</a>
      <form method="post" action="/post/${p.id}/delete" class="inline" data-confirm="Delete this article and all its comments?">${csrfField(ctx)}<button class="linkbtn" type="submit">Delete</button></form>
    </div>
  </li>`)}
</ul>`}`;
}

function auditPage({ rows }) {
  return html`<section class="page-head">
  <h1>Audit log</h1>
  <p class="muted">The latest ${rows.length} events: content changes and blocked attempts. Entries starting with “denied” or “csrf_blocked” are attacks or mistakes that were stopped.</p>
</section>
<div class="tablewrap"><table>
  <thead><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Target</th><th>IP</th></tr></thead>
  <tbody>
  ${rows.map((r) => html`<tr class="${/^(denied|csrf_blocked|login_throttled)/.test(r.action) ? 'bad' : ''}"><td>${r.ts}</td><td>${r.username || 'anonymous'}</td><td>${r.action}</td><td>${r.target_type ? `${r.target_type} #${r.target_id}` : ''}</td><td>${r.ip}</td></tr>`)}
  </tbody>
</table></div>`;
}

const ERROR_STAMPS = { 403: 'Denied', 404: 'Lost in the mail', 413: 'Too big', 415: 'Wrong format', 429: 'Slow down' };

function errorPage({ status, message }) {
  return html`<section class="errorpage">
  <h1 class="err-code">${status}</h1>
  <div class="slap static">${ERROR_STAMPS[status] || 'Something broke'}</div>
  <p class="err-msg">${message}</p>
  <p><a class="btn" href="/">Back to the home page</a></p>
</section>`;
}

/* ------------------------------------------------------------------ */
/* Security Lab                                                        */
/* ------------------------------------------------------------------ */

const PRESETS = [
  ['Script tag', "<script>alert('XSS')</script>"],
  ['Image handler', '<img src=x onerror="alert(document.cookie)">'],
  ['JavaScript link', '[Free gift](javascript:alert(1))'],
  ['Attribute escape', '"><svg onload=alert(1)>'],
  ['Normal formatting', '**Hello** *world*, see [the docs](https://example.com)'],
];

function labResult(payload) {
  const asTitle = html`${payload}`; // what a post title or username goes through
  const asBody = renderBody(payload); // article text
  const asComment = renderPlain(payload); // comment text
  const contexts = [
    { name: 'As an article title', out: asTitle, note: 'Every character is encoded.' },
    { name: 'As article text', out: asBody, note: 'Allowed formatting works. Everything else is encoded.' },
    { name: 'As a comment', out: asComment, note: 'Plain text only.' },
  ].map((c) => ({ ...c, check: inspectMarkup(String(c.out)) }));
  const safe = contexts.every(({ check }) => check.scripts + check.handlers + check.jsUrls === 0);
  return { contexts, safe };
}

function labPage({ ctx, payload, run = false, error }) {
  const result = run ? labResult(payload) : null;
  return html`<section class="lab">
  <div class="page-head">
    <h1>Security Lab</h1>
    <p class="lead">Paste something nasty and see exactly what the site does with it. The results below are the real output of the same code that renders articles and comments.</p>
  </div>

  <form method="post" action="/lab" class="form wide lab-form">
    ${csrfField(ctx)}
    <label for="payload">Your attack</label>
    <textarea id="payload" name="payload" rows="4" maxlength="2000" required placeholder="&lt;script&gt;alert(1)&lt;/script&gt;">${payload}</textarea>
    ${error ? html`<p class="field-error" role="alert">${error}</p>` : ''}
    <div class="presets" role="group" aria-label="Example attacks">
      ${PRESETS.map(([label, value]) => html`<button class="chip btnchip" type="button" data-fill="${value}">${label}</button>`)}
    </div>
    <button class="btn big" type="submit">Run it</button>
  </form>

  ${result ? html`<section class="results" aria-live="polite">
    <div class="verdict ${result.safe ? 'ok' : 'bad'}"><span class="slap static">${result.safe ? 'Neutralised' : 'Danger'}</span>
      <p>${result.safe ? 'No script, no event handler and no javascript: link in any output.' : 'Something dangerous got through.'}</p></div>
    <div class="trio">
    ${result.contexts.map((c) => html`<article class="lab-card">
      <h2>${c.name}</h2>
      <p class="muted">${c.note}</p>
      <div class="lab-render">${c.out}</div>
      <p class="lab-label">HTML the server sent</p>
      <pre class="lab-src"><code>${String(c.out)}</code></pre>
      <ul class="checks">
        <li class="${c.check.scripts ? 'no' : 'yes'}">${plural(c.check.scripts, 'script tag')}</li>
        <li class="${c.check.handlers ? 'no' : 'yes'}">${plural(c.check.handlers, 'event handler')}</li>
        <li class="${c.check.jsUrls ? 'no' : 'yes'}">${plural(c.check.jsUrls, 'javascript: link')}</li>
      </ul>
    </article>`)}
    </div>
  </section>` : ''}

  <section class="defences">
    <h2>Forged requests</h2>
    <p>A forged request is one sent by another website using your logged-in browser. This button sends one without the secret token every real form carries.</p>
    <div class="forge">
      <button class="btn danger" type="button" data-forge>Send a forged request</button>
      <p class="forge-out" id="forge-out" role="status">Not sent yet.</p>
    </div>
  </section>

  <section class="defences">
    <h2>What stands between an attacker and you</h2>
    <dl class="defence-list">
      <div><dt>XSS</dt><dd>Text is encoded before it reaches the page, formatting is limited to a short allowlist, and the browser is told never to run any script that did not come from this site.</dd></div>
      <div><dt>CSRF</dt><dd>Every change needs a per-session secret token, a matching Origin header, and a cookie that browsers will not send from other sites.</dd></div>
      <div><dt>Edits that are not yours</dt><dd>Ownership is checked in the code and again inside the database query. Every attempt is written to the audit log.</dd></div>
      <div><dt>Uploads</dt><dd>The real file type is read from its first bytes, the file gets a random name, and it is served with headers that stop a browser running it.</dd></div>
    </dl>
    <p class="muted">The content security policy sent with this page:</p>
    <pre class="lab-src"><code>${CSP.split('; ').join(';\n')}</code></pre>
  </section>
</section>`;
}

module.exports = {
  layout, home, searchPage, tagPage, profilePage, bookmarksPage, postPage, postForm, commentEditForm,
  authForm, dashboard, auditPage, errorPage, labPage,
};
