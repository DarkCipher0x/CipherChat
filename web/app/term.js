// DOM helpers for the chat terminal. Everything is built with createElement/textContent: message text from other
// people is never parsed as HTML. The only formatting is ```code blocks```, `inline code`, https links and @names.

export function el(tag, attrs, kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "cls") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of [].concat(kids || [])) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : String(c));
  return e;
}
export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }

export function hhmmss(unix) {
  const d = new Date(unix * 1000);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
}
export function ago(unix) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unix));
  if (s < 90) return s + "s";
  if (s < 5400) return Math.round(s / 60) + "m";
  if (s < 129600) return Math.round(s / 3600) + "h";
  return Math.round(s / 86400) + "d";
}

// Emoji: each one (a whole sequence: ZWJ families, skin tones, flags, keycaps) goes in <span class="emj">, drawn by the
// system's colour emoji font instead of the terminal's monospace font (which would draw some as flat outlines).
// Only emoji-style characters: text symbols like the terminal's own ☺ ↩ ✎ arrows stay as they are.
const EMOJI = /(?:\p{RI}\p{RI}|[0-9#*]️?⃣|(?:\p{Emoji_Presentation}|\p{Extended_Pictographic}️)[\u{1F3FB}-\u{1F3FF}]?(?:‍\p{Extended_Pictographic}️?[\u{1F3FB}-\u{1F3FF}]?)*|\u{1F3F4}[\u{E0061}-\u{E007A}]+\u{E007F})/gu;
export function emojify(text) {
  const out = [];
  let last = 0, m;
  EMOJI.lastIndex = 0;
  while ((m = EMOJI.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(el("span", { cls: "emj", text: m[0] }));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
// True when the text is only 1-3 emoji (and spaces): shown large.
export function isJumbo(text) {
  const t = text.trim();
  if (!t || t.length > 60) return false;
  const found = t.match(EMOJI);
  return !!found && found.length <= 3 && t.replace(EMOJI, "").trim() === "";
}

// Inline formatting of one plain-text run: `code`, https:// links, @mentions.
const INLINE = /(`[^`\n]{1,400}`)|(https:\/\/[^\s<>"'`]{2,2000})|(@[a-z0-9._-]{3,32})/g;
function inline(text, me) {
  const out = [];
  let last = 0, m;
  INLINE.lastIndex = 0;
  while ((m = INLINE.exec(text))) {
    if (m.index > last) out.push(...emojify(text.slice(last, m.index)));
    if (m[1]) out.push(el("code", { text: m[1].slice(1, -1) }));
    else if (m[2]) {
      let url = m[2].replace(/[).,;:!?]+$/, "");
      out.push(el("a", { href: url, rel: "noopener noreferrer nofollow", target: "_blank", referrerpolicy: "no-referrer", text: url }));
      if (url.length < m[2].length) out.push(m[2].slice(url.length));
    } else out.push(el("span", { cls: m[3].slice(1) === me ? "mention me" : "mention", text: m[3] }));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(...emojify(text.slice(last)));
  return out;
}

// Message text -> nodes. ``` fences become <pre> blocks (an optional language word after the fence is shown, not run).
export function richText(text, me) {
  const out = [];
  const parts = text.split(/```/);
  parts.forEach((part, i) => {
    if (i % 2 === 1 && i < parts.length - 1) {
      const nl = part.indexOf("\n");
      const lang = nl > 0 && /^[a-z0-9+#-]{1,20}$/i.test(part.slice(0, nl)) ? part.slice(0, nl) : "";
      const body = lang ? part.slice(nl + 1) : part.replace(/^\n/, "");
      out.push(el("pre", { "data-lang": lang || null, text: body.replace(/\n$/, "") }));
    } else {
      const t = i % 2 === 1 ? "```" + part : part;          // an unclosed fence stays literal
      if (t) out.push(...inline(t, me));
    }
  });
  return out;
}

// One log line: [time] <nick> text
export function line(kind, at, nick, content, opts) {
  opts = opts || {};
  const row = el("div", { cls: "ln " + kind, "data-seq": opts.seq || null });
  row.append(el("span", { cls: "ts", text: at ? hhmmss(at) : "" }));
  row.append(el("span", { cls: "nick" + (opts.mine ? " me" : ""), text: nick }));
  const txt = el("div", { cls: "txt" }, content);
  if (opts.tools) txt.append(el("span", { cls: "tools" }, opts.tools));
  row.append(txt);
  return row;
}

// A native modal <dialog> in the terminal style. build(body) may return {focus, value()}; buttons resolve the promise.
export function dialog(title, build, buttons) {
  return new Promise((resolve) => {
    const d = el("dialog", { cls: "term-dialog", "aria-label": title });
    d.append(el("h2", { text: title }));
    const body = el("div");
    d.append(body);
    const api = (build && build(body)) || {};
    const row = el("div", { cls: "gate-row" });
    for (const b of buttons) {
      row.append(el("button", { type: "button", cls: "term-btn " + (b.cls || ""), text: b.label, onclick: () => {
        const v = typeof b.value === "function" ? b.value(api) : b.value;
        if (v === false) return;
        d.close(); d.remove(); resolve(v === undefined ? null : v);
      } }));
    }
    d.append(row);
    d.addEventListener("cancel", () => { d.remove(); resolve(null); });
    document.body.append(d);
    d.showModal();
    if (api.focus) api.focus.focus();
  });
}
