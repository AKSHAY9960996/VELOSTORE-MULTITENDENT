/*
 * Event wiring that replaces inline onclick="..." / onchange="..." / onsubmit="..." attributes.
 * The Content-Security-Policy no longer allows inline event handlers, so templates use data attributes:
 *
 *   data-on-click="fnName"      call the global function fnName when the element is clicked
 *   data-on-change / data-on-input / data-on-keydown / data-on-submit   same, for those events
 *   data-args='[1, "text", "$el"]'   JSON arguments. "$el" = the element, "$value" = its value,
 *                                    "$event" = the event object
 *   data-confirm="Are you sure?"     ask first (on a button/link click or a form submit); "\n" = new line
 *   data-on-click="ui.submit"        built-ins: ui.submit, ui.remove, ui.reload, ui.clickId, ui.lettersOnly,
 *                                    ui.activateOnKey
 *
 * If the called function returns false, the default action (form submit / link) is cancelled.
 * Arguments travel as JSON in an attribute, never inside a JavaScript string, so product names or
 * other store-owner text can never turn into executable code.
 */
(function () {
  'use strict';

  var BUILTIN = {
    'ui.submit': function (el) { if (el.form) el.form.submit(); },
    'ui.remove': function (el) { el.remove(); },
    'ui.reload': function () { location.reload(); },
    'ui.clickId': function (el, ev, id) { var t = document.getElementById(id); if (t) t.click(); },
    'ui.lettersOnly': function (el) { el.value = el.value.replace(/[^A-Za-z\s.]/g, ''); },
    'ui.activateOnKey': function (el, ev) {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); el.click(); }
    }
  };

  function resolveArgs(el, ev) {
    var raw = el.getAttribute('data-args');
    if (!raw) return [];
    var list;
    try { list = JSON.parse(raw); } catch (e) { return []; }
    if (!Array.isArray(list)) return [];
    return list.map(function (a) {
      if (a === '$el') return el;
      if (a === '$value') return el.value;
      if (a === '$event') return ev;
      return a;
    });
  }

  function run(el, ev, type) {
    var name = el.getAttribute('data-on-' + type);
    if (!name) return;
    var result;
    if (Object.prototype.hasOwnProperty.call(BUILTIN, name)) {
      result = BUILTIN[name].apply(null, [el, ev].concat(resolveArgs(el, ev)));
    } else if (/^[A-Za-z_$][\w$]*$/.test(name) && typeof window[name] === 'function') {
      result = window[name].apply(window, resolveArgs(el, ev));
    } else {
      console.warn('ui-events: no function named', name);
      return;
    }
    if (result === false) ev.preventDefault();
  }

  function askConfirm(el, ev) {
    var msg = el.getAttribute('data-confirm');
    if (!msg) return true;
    if (window.confirm(msg.replace(/\\n/g, '\n'))) return true;
    ev.preventDefault();
    ev.stopPropagation();
    return false;
  }

  // Capture phase so a cancelled confirm stops everything else (like the old "return confirm(...)").
  document.addEventListener('click', function (ev) {
    var c = ev.target.closest && ev.target.closest('button[data-confirm],a[data-confirm],input[data-confirm]');
    if (c && !askConfirm(c, ev)) return;
    var el = ev.target.closest && ev.target.closest('[data-on-click]');
    if (el) run(el, ev, 'click');
  }, true);

  document.addEventListener('submit', function (ev) {
    var f = ev.target;
    if (f && f.matches && f.matches('form[data-confirm]') && !askConfirm(f, ev)) return;
    if (f && f.matches && f.matches('[data-on-submit]')) run(f, ev, 'submit');
  }, true);

  ['change', 'input', 'keydown'].forEach(function (type) {
    document.addEventListener(type, function (ev) {
      var el = ev.target.closest && ev.target.closest('[data-on-' + type + ']');
      if (el) run(el, ev, type);
    }, true);
  });
})();
