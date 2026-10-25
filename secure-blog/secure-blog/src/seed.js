'use strict';
/**
 * Sets the site up with:
 *   - an 'admin' account with a random password (printed once), if it does not exist yet
 *   - a few demo writers (nobody can log in as them: their passwords are random and never shown)
 *   - sample articles, tags, likes and comments, so the site does not start empty
 * Safe to run again: it adds demo content only while the site has fewer than 4 articles.
 * Usage: npm run seed
 */
const { openDatabase } = require('./db');
const createModels = require('./models');
const { hashPassword, randomToken } = require('./security');
const cfg = require('./config');

const ARTICLES = [
  {
    by: 'maya_codes', tags: ['security', 'xss', 'beginners'], likedBy: ['dev_kiran', 'nora', 'admin'],
    title: 'XSS in five minutes',
    body: 'Cross-site scripting happens when a site shows **user text as HTML**. Someone posts a comment containing a script tag, and every visitor\'s browser runs it.\n\nThe fix is boring and powerful: *encode everything on the way out*. The characters `<` and `>` become harmless text, so the browser never sees a tag.\n\nA second layer helps too. A strict Content-Security-Policy tells the browser to refuse any script that did not come from your own server, even if one slips through.',
  },
  {
    by: 'dev_kiran', tags: ['csrf', 'security'], likedBy: ['maya_codes', 'nora'],
    title: 'Why your logged-in browser is a weapon',
    body: 'Browsers attach your cookies to every request to a site, **even when another site triggers it**. That is CSRF: a page you visit quietly submits a form to your bank.\n\nThree defences work together: a secret token in every form, a check that the request really came from your own site, and cookies marked `SameSite=Strict`.\n\nNone of them is enough alone. All three together make forged requests very hard to land.',
  },
  {
    by: 'nora', tags: ['writing', 'notes'], likedBy: ['maya_codes'],
    title: 'Notes on writing in public',
    body: 'I used to keep every draft private. Then I started publishing the rough versions.\n\nThe surprise was not the feedback. It was that *finishing* things became easier once other people could see them.\n\nStart with something small. Hit publish before it feels ready.',
  },
  {
    by: 'maya_codes', tags: ['database', 'security'], likedBy: ['dev_kiran'],
    title: 'Never build SQL with string glue',
    body: 'If you paste user input into a query, a clever user can change the query. The cure is **prepared statements**: the query and the data travel separately, so data can never turn into commands.\n\nIt costs nothing and removes a whole class of attacks.',
  },
  {
    by: 'dev_kiran', tags: ['access-control', 'security'], likedBy: ['nora', 'maya_codes', 'admin'],
    title: 'Hiding the button is not security',
    body: 'A page that only shows the Delete button to the author is a nice touch. It is not protection, because anyone can send the request by hand.\n\nCheck ownership **on the server**, every time. Then check it again inside the database query, so even a forgotten check cannot hurt.',
  },
];

const COMMENTS = [
  ['XSS in five minutes', 'dev_kiran', 'The CSP point is the one people skip. Great summary.'],
  ['XSS in five minutes', 'nora', 'Finally an explanation I could follow without a headache.'],
  ['Hiding the button is not security', 'maya_codes', 'Checking twice, once in code and once in SQL, is a lovely habit.'],
];

(async () => {
  const db = openDatabase(cfg.dbFile);
  const m = createModels(db);

  let adminId = m.userByName('admin')?.id;
  if (!adminId) {
    const password = process.env.ADMIN_PASSWORD || randomToken(12);
    adminId = m.createUser('admin', await hashPassword(password), 'admin');
    m.createPost(adminId, {
      title: 'Welcome to Inkproof',
      body: 'This blog stops **XSS**, **CSRF** and edits that are not yours.\n\nCreate an account, write an article, then visit the Security Lab and try to break it.',
      published: true,
      tags: ['welcome'],
    });
    console.log(`Admin account created.\n  username: admin\n  password: ${password}\nStore this password now; it is not shown again.`);
  } else {
    console.log('The "admin" account already exists.');
  }

  if (m.countPublished() >= 4) {
    console.log('The site already has articles; no demo content added.');
    return;
  }

  const ids = { admin: adminId };
  for (const name of ['maya_codes', 'dev_kiran', 'nora']) {
    ids[name] = m.userByName(name)?.id ?? m.createUser(name, await hashPassword(randomToken(24)));
  }
  const postIds = {};
  for (const a of ARTICLES) {
    postIds[a.title] = m.createPost(ids[a.by], { title: a.title, body: a.body, published: true, tags: a.tags });
    for (const who of a.likedBy) m.toggleLike(postIds[a.title], ids[who]);
  }
  for (const [title, who, body] of COMMENTS) m.createComment(postIds[title], ids[who], body);
  console.log(`Added ${ARTICLES.length} demo articles from 3 demo writers.`);
})();
