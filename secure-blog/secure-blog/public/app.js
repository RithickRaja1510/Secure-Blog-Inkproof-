/* Inkproof front-end behaviour. Loaded from our own origin only (CSP: script-src 'self').
 * Rules for this file: never build HTML from strings, never use innerHTML/eval; only textContent,
 * attributes and classes. Everything also works with JavaScript turned off. */
(function () {
  'use strict';
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* Character counters */
  $$('[data-count]').forEach(function (el) {
    var out = $('[data-counter-for="' + el.id + '"]');
    if (!out) return;
    var max = Number(el.getAttribute('data-count'));
    var update = function () {
      out.textContent = el.value.length + ' / ' + max;
      out.classList.toggle('near', el.value.length > max * 0.9);
    };
    el.addEventListener('input', update);
    update();
  });

  /* Cover image: instant preview and a friendly size/type check (the server re-checks everything) */
  $$('input[type=file][data-preview]').forEach(function (input) {
    var img = document.getElementById(input.getAttribute('data-preview'));
    var err = document.getElementById('cover-error');
    var max = Number(input.getAttribute('data-max')) || 0;
    var ok = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
    var show = function (msg) {
      if (!err) return;
      err.textContent = msg || '';
      err.hidden = !msg;
    };
    input.addEventListener('change', function () {
      var f = input.files && input.files[0];
      show('');
      if (!f) { if (img) img.hidden = true; return; }
      if (ok.indexOf(f.type) < 0) { input.value = ''; if (img) img.hidden = true; show('Only PNG, JPG, GIF or WebP images are accepted.'); return; }
      if (max && f.size > max) { input.value = ''; if (img) img.hidden = true; show('That image is larger than 1.5 MB. Choose a smaller one.'); return; }
      if (img) { img.src = URL.createObjectURL(f); img.hidden = false; }
    });
  });

  /* Password strength meter (length and variety; purely a hint) */
  $$('[data-meter-for]').forEach(function (meter) {
    var input = document.getElementById(meter.getAttribute('data-meter-for'));
    var bars = $$('i', meter);
    if (!input) return;
    input.addEventListener('input', function () {
      var v = input.value;
      var score = 0;
      if (v.length >= 10) score++;
      if (v.length >= 14) score++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
      if (/\d/.test(v) && /[^A-Za-z0-9]/.test(v)) score++;
      bars.forEach(function (b, i) { b.className = i < score ? 'on s' + score : ''; });
    });
  });

  /* Confirm before destructive actions */
  $$('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.getAttribute('data-confirm'))) e.preventDefault();
    });
  });

  /* Security Lab: preset payloads */
  $$('[data-fill]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var box = document.getElementById('payload');
      if (box) { box.value = btn.getAttribute('data-fill'); box.focus(); }
    });
  });

  /* Security Lab: a real forged request (same origin, but without the CSRF token) */
  $$('[data-forge]').forEach(function (btn) {
    var out = document.getElementById('forge-out');
    btn.addEventListener('click', function () {
      btn.disabled = true;
      out.textContent = 'Sending…';
      fetch('/lab/forged-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=delete-everything',
        credentials: 'same-origin'
      }).then(function (res) {
        out.textContent = res.status === 403
          ? 'Blocked with status 403. The request had no valid secret token, so nothing happened.'
          : 'The server answered with status ' + res.status + '.';
        out.className = 'forge-out ' + (res.status === 403 ? 'blocked' : '');
      }).catch(function () {
        out.textContent = 'The request could not be sent.';
      }).then(function () { btn.disabled = false; });
    });
  });

  /* Hero: attacks arriving, each one neutralised */
  var deck = document.getElementById('deck');
  if (deck && !reduce) {
    var attacks = [
      ['<script>alert(1)</script>', 'Shown as plain text. Nothing ran.'],
      ['<img src=x onerror=steal()>', 'Shown as plain text. The image never loaded.'],
      ['[free gift](javascript:alert(1))', 'Never became a link.'],
      ['POST /post/7/delete from evil.example', 'Refused. The request came from another site.'],
      ['" onmouseover="alert(1)', 'Encoded. The quote could not break out.']
    ];
    var payload = document.getElementById('deck-payload');
    var out = document.getElementById('deck-out');
    var slap = document.getElementById('deck-slap');
    var i = 0;
    setInterval(function () {
      i = (i + 1) % attacks.length;
      payload.textContent = attacks[i][0];
      out.textContent = attacks[i][1];
      slap.classList.remove('hit');
      void slap.offsetWidth; // restart the animation
      slap.classList.add('hit');
    }, 4200);
    slap.classList.add('hit');
  }

  /* Cards tilt toward the pointer */
  if (!reduce && window.matchMedia('(hover: hover)').matches) {
    $$('.stamp-wrap').forEach(function (el) {
      el.addEventListener('pointermove', function (e) {
        var r = el.getBoundingClientRect();
        var x = (e.clientX - r.left) / r.width - 0.5;
        var y = (e.clientY - r.top) / r.height - 0.5;
        el.style.setProperty('--ry', (x * 6).toFixed(2) + 'deg');
        el.style.setProperty('--rx', (-y * 6).toFixed(2) + 'deg');
      });
      el.addEventListener('pointerleave', function () {
        el.style.setProperty('--ry', '0deg');
        el.style.setProperty('--rx', '0deg');
      });
    });
  }

  /* Reading progress bar (browsers without scroll-driven animations) */
  var bar = $('.progress');
  if (bar && !(window.CSS && CSS.supports && CSS.supports('animation-timeline: scroll()'))) {
    var tick = function () {
      var h = document.documentElement;
      var max = h.scrollHeight - h.clientHeight;
      bar.style.setProperty('--p', max > 0 ? String(Math.min(1, h.scrollTop / max)) : '0');
    };
    window.addEventListener('scroll', tick, { passive: true });
    tick();
  }
})();
