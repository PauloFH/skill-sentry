/* skill-sentry landing page: language toggle, copy buttons, scroll reveal.
   No requests, no third parties. English lives in the HTML; Portuguese comes from the
   <script type="application/json" id="i18n"> block. Without JS the page stays in English. */
(function () {
  'use strict';
  var root = document.documentElement;
  root.classList.add('js');

  var STORE_KEY = 'ss-lang';
  var LANGS = { en: 'en', pt: 'pt-BR' };

  function storedLang() {
    try { return window.localStorage.getItem(STORE_KEY); } catch (e) { return null; }
  }
  function storeLang(lang) {
    try { window.localStorage.setItem(STORE_KEY, lang); } catch (e) { /* private mode: keep it for this visit only */ }
  }

  function setup() {
    var dict = {};
    try { dict = JSON.parse(document.getElementById('i18n').textContent); } catch (e) { dict = {}; }

    var textNodes = Array.prototype.slice.call(document.querySelectorAll('[data-i18n]'));
    var attrNodes = Array.prototype.slice.call(document.querySelectorAll('[data-i18n-attr]'));

    // Capture the English markup once so switching back restores it exactly.
    var en = textNodes.map(function (el) { return el.innerHTML; });
    var enAttrs = attrNodes.map(function (el) {
      return pairs(el).map(function (p) { return el.getAttribute(p.attr); });
    });

    function pairs(el) {
      return el.getAttribute('data-i18n-attr').split(',').map(function (s) {
        var parts = s.split(':');
        return { attr: parts[0].trim(), key: parts[1].trim() };
      });
    }

    var current = 'en';
    var buttons = Array.prototype.slice.call(document.querySelectorAll('[data-lang]'));

    function apply(lang) {
      if (!LANGS[lang] || (lang !== 'en' && !dict[lang])) lang = 'en';
      var table = dict[lang] || {};
      textNodes.forEach(function (el, i) {
        var v = lang === 'en' ? en[i] : table[el.getAttribute('data-i18n')];
        if (typeof v === 'string' && el.innerHTML !== v) el.innerHTML = v;
      });
      attrNodes.forEach(function (el, i) {
        pairs(el).forEach(function (p, j) {
          var v = lang === 'en' ? enAttrs[i][j] : table[p.key];
          if (typeof v === 'string') el.setAttribute(p.attr, v);
        });
      });
      root.setAttribute('lang', LANGS[lang]);
      buttons.forEach(function (b) {
        b.setAttribute('aria-pressed', String(b.getAttribute('data-lang') === lang));
      });
      current = lang;
    }

    var toggle = document.querySelector('.lang');
    if (toggle && dict.pt) {
      toggle.hidden = false;
      buttons.forEach(function (b) {
        b.addEventListener('click', function () {
          var lang = b.getAttribute('data-lang');
          if (lang === current) return;
          apply(lang);
          storeLang(lang);
        });
      });
      var saved = storedLang();
      if (saved === 'pt') apply('pt');
    }

    setupCopy();
    setupReveal();
    setupHeader();
  }

  /* ---------- Copy buttons ---------- */

  function uiText(id) {
    var el = document.getElementById(id);
    return el ? el.textContent : '';
  }

  function selectNodes(nodes) {
    var sel = window.getSelection && window.getSelection();
    if (!sel || !document.createRange) return false;
    var range = document.createRange();
    range.setStart(nodes[0], 0);
    range.setEnd(nodes[nodes.length - 1], nodes[nodes.length - 1].childNodes.length);
    sel.removeAllRanges();
    sel.addRange(range);
    return true;
  }

  function legacyCopy(nodes) {
    // Works on file:// and plain http where the async Clipboard API is missing or refuses.
    // The text stays selected either way, so Ctrl+C is the manual fallback.
    if (!selectNodes(nodes)) return false;
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    return ok;
  }

  function setupCopy() {
    var status = document.getElementById('copy-status');
    var timer = null;

    function report(btn, ok) {
      if (status) {
        status.textContent = uiText(ok ? 't-copied' : 't-selected');
        clearTimeout(timer);
        timer = setTimeout(function () { status.textContent = ''; }, 2600);
      }
      if (ok) {
        btn.classList.add('done');
        setTimeout(function () { btn.classList.remove('done'); }, 1600);
      }
    }

    Array.prototype.slice.call(document.querySelectorAll('[data-copy]')).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var ids = btn.getAttribute('data-copy').split(/\s+/);
        var nodes = ids.map(function (id) { return document.getElementById(id); }).filter(Boolean);
        if (!nodes.length) return;
        var text = nodes.map(function (n) { return n.textContent.trim(); }).join('\n');

        function fallback() { report(btn, legacyCopy(nodes)); }

        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          try {
            navigator.clipboard.writeText(text).then(function () { report(btn, true); }, fallback);
          } catch (e) { fallback(); }
        } else {
          fallback();
        }
      });
    });
  }

  /* ---------- Scroll reveal ---------- */

  function setupReveal() {
    var items = Array.prototype.slice.call(document.querySelectorAll('.reveal'));
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce || !('IntersectionObserver' in window)) {
      items.forEach(function (el) { el.classList.add('in'); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.12 });
    items.forEach(function (el) { io.observe(el); });
  }

  /* ---------- Header border once scrolled ---------- */

  function setupHeader() {
    var header = document.querySelector('.site-header');
    if (!header) return;
    var onScroll = function () { header.classList.toggle('scrolled', window.scrollY > 8); };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup);
  } else {
    setup();
  }
})();
