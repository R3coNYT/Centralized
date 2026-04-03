/* =========================================================
   custom-select.js
   Auto-converts every <select class="form-select"> into a
   fully styleable Bootstrap dropdown (ul/li), while keeping
   the original <select> hidden for form submission.
   ========================================================= */
(function () {
  'use strict';

  /* ── Build a single custom select ─────────────────────── */
  function buildCustomSelect(sel) {
    if (sel.dataset.csConverted) return;
    sel.dataset.csConverted = '1';

    const isSmall    = sel.classList.contains('form-select-sm');
    const isDisabled = sel.disabled;

    /* ── Helpers ── */
    function selectedText()  { const o = sel.options[sel.selectedIndex]; return o ? o.text  : ''; }
    function selectedValue() { return sel.value; }

    /* ── Wrapper ── */
    const wrapper = document.createElement('div');
    wrapper.className = 'cs-wrapper dropdown';
    /* Copy width-related classes from the original select */
    ['w-100', 'w-75', 'w-50', 'w-25', 'flex-grow-1'].forEach(c => {
      if (sel.classList.contains(c)) wrapper.classList.add(c);
    });
    if (isDisabled) wrapper.classList.add('cs-disabled');

    /* ── Toggle button ── */
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cs-toggle btn w-100 d-flex align-items-center justify-content-between' + (isSmall ? ' btn-sm' : '');
    btn.setAttribute('data-bs-toggle', 'dropdown');
    btn.setAttribute('aria-expanded', 'false');
    btn.disabled = isDisabled;
    btn.innerHTML =
      '<span class="cs-label text-truncate">' + escHtml(selectedText()) + '</span>' +
      '<i class="bi bi-chevron-down cs-chevron ms-2 flex-shrink-0" aria-hidden="true"></i>';

    /* ── Dropdown menu ── */
    const menu = document.createElement('ul');
    menu.className = 'cs-menu dropdown-menu w-100';

    function buildOptions() {
      menu.innerHTML = '';
      Array.from(sel.options).forEach(function (opt) {
        var li = document.createElement('li');
        if (opt.disabled && !opt.value) {
          /* Placeholder / disabled header */
          li.innerHTML = '<span class="dropdown-item cs-item cs-placeholder disabled">' + escHtml(opt.text) + '</span>';
        } else if (opt.disabled) {
          li.innerHTML = '<span class="dropdown-item cs-item cs-item-disabled disabled text-muted">' + escHtml(opt.text) + '</span>';
        } else {
          var a = document.createElement('a');
          a.className = 'dropdown-item cs-item' + (opt.value === selectedValue() ? ' active' : '');
          a.href = '#';
          a.dataset.value = opt.value;
          a.textContent = opt.text;
          a.addEventListener('click', function (e) {
            e.preventDefault();
            sel.value = opt.value;
            btn.querySelector('.cs-label').textContent = opt.text;
            menu.querySelectorAll('.cs-item.active').forEach(function (i) { i.classList.remove('active'); });
            a.classList.add('active');
            sel.dispatchEvent(new Event('change', { bubbles: true }));
          });
          li.appendChild(a);
        }
        menu.appendChild(li);
      });
    }

    buildOptions();
    wrapper.appendChild(btn);
    wrapper.appendChild(menu);

    /* ── Hide native select, inject wrapper right after it ── */
    /* Keep select in DOM for form serialisation */
    sel.style.cssText += 'position:absolute;width:1px;height:1px;opacity:0;pointer-events:none;';
    sel.setAttribute('aria-hidden', 'true');
    sel.parentNode.insertBefore(wrapper, sel.nextSibling);

    /* ── Re-sync when options are added/changed via JS ── */
    var optObserver = new MutationObserver(function () {
      buildOptions();
      btn.querySelector('.cs-label').textContent = escHtml(selectedText());
    });
    optObserver.observe(sel, { childList: true, subtree: true });

    /* ── Sync if .value is set programmatically ── */
    var valueProxy = setInterval(function () {
      var currentVal = selectedValue();
      var activeItem  = menu.querySelector('.cs-item.active');
      if (activeItem && activeItem.dataset.value !== currentVal) {
        buildOptions();
        btn.querySelector('.cs-label').textContent = escHtml(selectedText());
      }
    }, 500);

    /* Clean up interval if wrapper is removed */
    var removeObserver = new MutationObserver(function () {
      if (!document.contains(wrapper)) {
        clearInterval(valueProxy);
        removeObserver.disconnect();
      }
    });
    removeObserver.observe(document.body, { childList: true, subtree: true });
  }

  /* ── HTML-escape helper ────────────────────────────────── */
  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* ── Initialise all existing selects ───────────────────── */
  function initAll() {
    document.querySelectorAll('select.form-select:not([data-cs-converted])').forEach(buildCustomSelect);
  }

  /* ── Watch for dynamically added selects ───────────────── */
  function watchDOM() {
    var bodyObserver = new MutationObserver(function (mutations) {
      mutations.forEach(function (m) {
        m.addedNodes.forEach(function (node) {
          if (node.nodeType !== 1) return;
          if (node.matches && node.matches('select.form-select')) {
            buildCustomSelect(node);
          }
          if (node.querySelectorAll) {
            node.querySelectorAll('select.form-select:not([data-cs-converted])').forEach(buildCustomSelect);
          }
        });
      });
    });
    bodyObserver.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { initAll(); watchDOM(); });
  } else {
    initAll();
    watchDOM();
  }

  /* ── Public API (optional programmatic call) ─────────────*/
  window.customSelectInit = initAll;
})();
