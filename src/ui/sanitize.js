// HTML safety layer.
//   1. Almost all UI text is set with textContent (never parsed as HTML).
//   2. The ONLY path for HTML is richText(), which runs a tightly configured
//      DOMPurify (tiny allow-list, zero attributes, no URLs) and returns a
//      TrustedHTML value from a named Trusted Types policy.
//   3. The CSP enforces `require-trusted-types-for 'script'`, so any other
//      innerHTML / eval / script-URL sink throws instead of executing.
import DOMPurify from 'dompurify';

const PURIFY = {
  ALLOWED_TAGS: ['b', 'strong', 'i', 'em', 'u', 's', 'code', 'br', 'p'],
  ALLOWED_ATTR: [],
  ALLOW_DATA_ATTR: false,
  ALLOW_ARIA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  FORBID_TAGS: ['style', 'script', 'svg', 'math', 'iframe', 'object', 'embed', 'form', 'template'],
  FORBID_ATTR: ['style', 'onerror', 'onload', 'onclick', 'href', 'src', 'srcset', 'action', 'formaction'],
  KEEP_CONTENT: true,
  RETURN_TRUSTED_TYPE: false,
  SANITIZE_DOM: true,
  SANITIZE_NAMED_PROPS: true,
  WHOLE_DOCUMENT: false,
};

// Belt and braces: strip any attribute at all, even if a future config change allows one.
let strict = false;
DOMPurify.addHook('uponSanitizeAttribute', (_node, data) => { if (strict) data.keepAttr = false; });
function purifyStrict(s) { strict = true; try { return DOMPurify.sanitize(s, PURIFY); } finally { strict = false; } }

let policy = null;
if (globalThis.trustedTypes?.createPolicy) {
  policy = trustedTypes.createPolicy('wekonet', {
    createHTML: (s) => purifyStrict(s),
    // No script / script-URL creation is permitted at all.
    createScript: () => { throw new TypeError('WeKoNet: dynamic script blocked'); },
    createScriptURL: () => { throw new TypeError('WeKoNet: dynamic script URL blocked'); },
  });
}

// 'default' policy: catches string→HTML sinks used inside third-party libraries
// (e.g. Leaflet's attribution control). Only plain https links survive.
const LIB = {
  ALLOWED_TAGS: ['a', 'span', 'div', 'b', 'strong', 'br'],
  ALLOWED_ATTR: ['href', 'title', 'class', 'target', 'rel', 'aria-hidden'],
  ALLOWED_URI_REGEXP: /^https:\/\//i,
  FORBID_TAGS: ['style', 'script', 'svg', 'math', 'iframe', 'object', 'embed', 'form', 'img'],
};
if (globalThis.trustedTypes?.createPolicy) {
  try {
    trustedTypes.createPolicy('default', {
      createHTML: (s) => DOMPurify.sanitize(String(s), LIB),
      createScript: () => { throw new TypeError('WeKoNet: dynamic script blocked'); },
      createScriptURL: (u) => {
        // Only our own bundled worker may be loaded.
        const url = new URL(u, location.href);
        if (url.origin === location.origin) return url.href;
        throw new TypeError('WeKoNet: foreign script URL blocked');
      },
    });
  } catch { /* already defined */ }
}

/** Sanitize untrusted text that may contain light formatting. */
export function richText(untrusted) {
  const s = String(untrusted ?? '').slice(0, 8000);
  return policy ? policy.createHTML(s) : purifyStrict(s);
}

export function setRich(el, untrusted) { el.innerHTML = richText(untrusted); }

/** Safe element builder — text only, event handlers via addEventListener. */
export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'href') {
      // Links: absolute https:// only (no javascript:, data:, relative tricks), always
      // opened as a separate tab with no opener and no referrer.
      if (tag !== 'a' || !/^https:\/\/[^\s"'<>]+$/i.test(String(v))) throw new Error('h(): only https links are allowed');
      el.href = String(v); el.target = '_blank'; el.rel = 'noopener noreferrer';
    } else if ((k === 'target' && v === '_blank') || (k === 'rel' && /^noopener( noreferrer)?$/.test(v))) { /* set together with href */ }
    else if (/^(aria-|role$|type$|id$|for$|name$|value$|placeholder$|title$|disabled$|checked$|autocomplete$|inputmode$|maxlength$|tabindex$|playsinline$|autoplay$|muted$)/.test(k)) {
      if (k === 'value' || k === 'checked' || k === 'muted') el[k] = v; else el.setAttribute(k, v === true ? '' : String(v));
    } else throw new Error(`h(): attribute "${k}" not allowed`);
  }
  for (const c of children.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
