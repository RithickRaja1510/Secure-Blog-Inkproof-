# Inkproof

A secure blogging platform: users publish articles with cover images, comment, like, save and search.
Built for the **Secure Software Engineering** mini project. It defends against **XSS**, **CSRF** and
**unauthorised content modification**, and every defence is covered by an automated attack test.

It has **zero third-party dependencies**: only Node's built-in `http`, `node:sqlite` and `crypto`,
so each security control is visible in the project's own code.

## Run it

Requires **Node.js 22.13 or newer** (tested on 22 and 24).

```bash
npm run seed     # creates the 'admin' account (random password, printed once) and sample articles
npm start        # http://127.0.0.1:3000
npm test         # 59 attack-simulation tests
```

Upgrading from the first version? Just run `npm start` again. The database is upgraded in place and
all existing accounts, posts and comments are kept.

| Environment variable | Meaning | Default |
|---|---|---|
| `PORT`, `HOST` | listen address | `3000`, `127.0.0.1` |
| `DB_FILE` | SQLite file | `data/blog.db` |
| `UPLOAD_DIR` | where cover images are stored (never inside `public/`) | `data/uploads` |
| `COOKIE_SECURE=1` | `Secure` + `__Host-` cookie and HSTS (use behind HTTPS) | off |
| `TRUST_PROXY=1` | take client IP from `X-Forwarded-For` (only behind your own proxy) | off |

## Features

- **Accounts**: register, log in, log out, profile pages
- **Articles**: write, edit, delete; private drafts or published; **cover image upload**; up to 5 **tags**
- **Comments**: add, edit your own, delete (author, article owner or admin)
- **Likes and bookmarks**: one per user per article; a "Saved" page
- **Search** by title, text or tag; tag pages; "Latest" and "Most liked" sorting
- **Security Lab**: paste any attack and see exactly what the site does with it, and send a real forged request
- **Admin audit log** of every content change and every blocked attack
- **Design**: every article is a postage stamp with a postmark; responsive, keyboard accessible, respects reduced motion

## Threat model and defences

### 1. Cross-site scripting (XSS)

| Attack | Defence | Where |
|---|---|---|
| Stored XSS in titles, posts, comments, tags | **Auto-escaping template tag** `html```: every `${value}` is HTML-encoded unless it came from another `html``/`raw()` call. Forgetting to escape is not possible by accident. | `src/security.js`, `src/views.js` |
| Rich text in posts | **Restricted markup renderer** (`**bold**`, `*italic*`, `` `code` ``, `[text](url)`). Text is escaped *first*; tags are added afterwards. Links must be `http(s)` with no embedded credentials; `javascript:` and `data:` are never linked. Comments are plain text only. | `renderBody`, `renderPlain` |
| Reflected XSS (search box, form re-display) | Same escaping on every echoed value | `src/views.js` |
| Attribute break-out (e.g. a title inside `alt="..."`) | Quotes are encoded, so a value can never leave its attribute | `esc()` |
| Injected script that slips through anyway | **Content-Security-Policy**: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. No inline script, no inline handler, no `eval`, nothing from other sites. | `src/headers.js` |
| MIME sniffing, clickjacking, referrer leaks | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, explicit `charset=utf-8` | `src/headers.js` |
| Cookie theft via script | Session cookie is `HttpOnly` | `src/server.js` |
| Text spoofing | Control and bidi-override characters stripped from input | `cleanText` |
| The page's own JavaScript | `public/app.js` never uses `innerHTML` or `eval`; it only sets `textContent`, attributes and classes | `public/app.js` |

> Note: version 1 forbade *all* scripts. The redesign needs a small script (counters, image preview,
> Security Lab), so the policy now allows scripts **from our own origin only**. Inline scripts remain forbidden.

### 2. Cross-site request forgery (CSRF)

Three independent layers protect every state-changing request (all `POST`; no `GET` changes data):

1. **Synchronizer token**: a random 256-bit token per session, embedded in every form (including upload forms), compared in constant time.
2. **Origin / Referer check**: the request must come from this site's own host. It runs *before* the body is read, so a forged upload is rejected without being processed. `Origin: null`, foreign origins, or no Origin *and* no Referer are rejected.
3. **`SameSite=Strict` cookie**: browsers do not send the session cookie on cross-site requests.

Login, logout, likes, bookmarks and the lab are protected too. Blocked attempts are written to the audit log.
Session hardening: server-side sessions, only a SHA-256 of the session id stored in the DB, **new session id on login** (fixation), idle (30 min) and absolute (8 h) expiry, logout destroys the session server-side.

### 3. Unauthorised content modification

| Rule | Enforcement |
|---|---|
| Only the author (or an admin) can edit or delete a post, change or remove its cover | `src/authz.js` policy checked in every handler **and** repeated in the SQL `WHERE` clause, so a missed check cannot modify someone else's data |
| Drafts (and their cover images) are private; for outsiders they look like `404` | `canViewPost`, `/uploads` lookup |
| Only the author can change the words of a comment (not even the post owner or admin) | `canEditComment` + SQL condition |
| Comments can be deleted by their author, the post owner (moderation) or an admin | `canDeleteComment` + SQL condition |
| Client cannot choose the author, role or cover name (**mass assignment**) | handlers read an explicit whitelist of fields; `author_id` always comes from the session; cover names are generated by the server |
| IDs in URLs (**IDOR**) | validated as digits, used only to *look up* records, then authorised |
| Drafts cannot be liked or bookmarked; likes are one per user | handler check + primary key `(post_id, user_id)` |
| Every change and every denied attempt is recorded | `audit_log` table, viewable by admins at `/admin/audit` |

### 4. Secure file uploads (`src/upload.js`)

- Hand-written `multipart/form-data` parser with hard limits (body size, number of parts, header size); multipart is accepted **only** on the two routes that take a cover (`/new`, `/post/:id/edit`)
- The client's file name and `Content-Type` are **ignored**. The real type is decided from the file's **magic bytes**; only PNG, JPEG, GIF and WebP are accepted (no SVG or HTML, which can carry script)
- Stored under a random 128-bit name in a directory outside the web root; names are re-validated on every read (no path traversal)
- Served from `/uploads/<name>` with a type taken from our own table, `nosniff`, and `Content-Security-Policy: default-src 'none'; sandbox`, so even a script hidden inside a GIF is never executed
- Limit 1.5 MB per image; old files are deleted when a cover is replaced or its post is deleted

### Other controls

- **SQL injection**: prepared statements with bound parameters everywhere (`src/models.js`); search escapes `%`, `_` and `\` so wildcards match literally
- **Passwords**: scrypt with a per-user salt; 10 to 128 characters; constant-time verification
- **Brute force**: 5 failed logins per IP+username and 30 per IP per 15 minutes returns `429`; a dummy hash is checked for unknown users so timing does not reveal which usernames exist; generic error message
- **Rate limits**: global per IP, sign-ups, comments, likes/bookmarks, searches
- **Input limits**: title 150, post 20,000, comment 2,000, search 80 characters; request body 64 KB (1.6 MB for uploads); tags `[a-z0-9-]{1,24}`, at most 5
- **No information leaks**: unexpected errors return a generic message (stack traces only in the server log); static files come from a fixed allowlist
- **Safe redirects**: only local paths; no `?next=` parameter, so no open redirect

## Tests (`npm test`)

`test/security.test.js` plays the attacker against a real running server (59 tests):

- **XSS**: script, img, svg and attribute break-out payloads in titles, bodies, comments, search and form fields; `javascript:` and credentialed links; CSP and header checks; no inline script, style or handler anywhere
- **CSRF**: missing, wrong, empty and foreign-session tokens; cross-site and `null` Origin; missing Origin; forged login and logout; no state-changing GETs; cookie flags; multipart forms
- **Authentication**: hashed passwords, session fixation, logout invalidation, user enumeration, brute-force lockout, weak passwords
- **Unauthorised modification**: anonymous, non-owner edit and delete, hidden-field tampering, draft visibility, comment rules, admin rights, IDOR and SQL-injection ids, audit log
- **Uploads**: HTML, SVG and executables disguised as images, a script hidden in a GIF, size limits, path traversal, private draft covers, non-owner cover replacement, file clean-up, malformed multipart
- **Likes, search, tags, profiles, Security Lab**: toggling, drafts, privacy of bookmarks, `%`/`_`/quote injection in search, tag validation, profile lookups, forged lab request
- **Robustness**: oversized bodies, over-long fields, wrong content types, path traversal, bidi characters

**The tests can fail.** The defences were deliberately broken one at a time to check the tests notice:
disabling output escaping fails 10 tests, the CSRF token check 7, the Origin check 3, the magic-byte check 2, and the
ownership check in the handler 1 (the SQL `WHERE` clause still blocked the attack: defence in depth working).

## Project layout

```
src/server.js    HTTP server, CSRF checks, request context, multipart reading, error handling
src/headers.js   Content-Security-Policy and the other security headers
src/routes.js    URL handlers (every authorization decision goes through authz.js)
src/authz.js     the access-control policy in one place
src/security.js  escaping, markup renderer, password hashing, validation, rate limiter
src/upload.js    multipart parser, image type sniffing, upload store
src/models.js    prepared-statement data layer (authorization repeated in SQL)
src/sessions.js  server-side session store
src/views.js     HTML templates (auto-escaped)
src/db.js        SQLite schema and upgrade of older databases
src/seed.js      first admin account and sample articles
public/          style.css, app.js, favicon.svg (the only static files)
test/            attack-simulation tests
```

## Known limitations (state these in your report)

- Serve it over **HTTPS** in production (set `COOKIE_SECURE=1`); the app cannot add TLS by itself.
- Rate-limit counters are in memory, so they reset on restart and are per process.
- No email verification, password reset or two-factor authentication.
- Uploaded images are not re-encoded or scanned; safety relies on type checking plus the serving headers.
- Lockout is per IP+username so an attacker cannot lock a victim out everywhere, but a shared IP can still be throttled.
- The design uses system fonts (no downloads), so headings look slightly different on Windows, macOS and Linux.
