// How verified messages appear in a room: text, actions, replies, edits, reactions and attachments. Everything here has
// already passed openMessage() (signature from a trusted identity, decrypted with the room key); this only decides how
// it looks and how later events (reactions, edits) change earlier messages. Reactions and edits are ordinary signed,
// encrypted messages, so every device that reads the room shows exactly the same state.
import * as C from "./crypto.js";
import { el, clear, line, richText, dialog, emojify, isJumbo } from "./term.js";
import { downloadBlob } from "./api.js";

export function init(R) {
  R.msgs = new Map();          // message id -> {id, seq, from, at, payload, row, body, files, chips, ops, edited}
  R.pending = new Map();       // target id -> [{kind, from, seq, payload}] (reactions/edits that arrived first)
  R.urls = [];                 // blob: URLs made for this room (released when the page reloads/locks)
}

const human = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
const safeName = (s) => String(s).replace(/[\x00-\x1f\x7f/\\:*?"<>|]+/g, "_").slice(0, 120) || "attachment";

// ------------------------------------------------------------------------------------------------ entry point
// ctx: {me, older, place(row), canDel(from), onReact(id, emoji, on), onReply(m), onEdit(m), onDelete(seq), log(text)}
export function show(R, it, header, payload, ctx) {
  const kind = payload.k || "text";
  if (kind === "react" || kind === "edit") {
    const op = { kind, from: it.from, seq: it.seq, payload };
    const m = R.msgs.get(payload.target);
    if (m) apply(R, m, op, ctx); else { if (!R.pending.has(payload.target)) R.pending.set(payload.target, []); R.pending.get(payload.target).push(op); }
    return false;                                         // nothing new to show in the log
  }
  const m = { id: header.id, seq: it.seq, from: it.from, at: it.at, payload, ops: new Map(), edited: 0 };
  const mine = it.from === ctx.me;
  if (payload.burn) return showBurn(R, m, it, kind, mine, ctx);
  const tools = [
    el("button", { type: "button", title: "React", "aria-label": "React", text: "☺", onclick: (ev) => ctx.onReactMenu(m, ev.currentTarget) }),
    el("button", { type: "button", title: "Reply", "aria-label": "Reply", text: "↩", onclick: () => ctx.onReply(m) }),
    mine && kind !== "file" ? el("button", { type: "button", title: "Edit", "aria-label": "Edit", text: "✎", onclick: () => ctx.onEdit(m) }) : null,
    ctx.canDel(it.from) ? el("button", { type: "button", title: "Delete for everyone", "aria-label": "Delete", text: "del", onclick: () => ctx.onDelete(it.seq) }) : null,
  ].filter(Boolean);
  m.body = el("span", { cls: "body" });
  setText(m, payload.text, ctx.me, kind === "me" ? it.from : null);
  const parts = [];
  if (payload.re) parts.push(quote(R, payload.re));
  parts.push(m.body);
  if (kind === "file") { m.files = el("div", { cls: "att-list" }); parts.push(m.files); for (const f of payload.files) m.files.append(fileView(R, f, ctx)); }
  m.chips = el("div", { cls: "react-row" });
  parts.push(m.chips);
  m.row = kind === "me" ? line("act", it.at, "*", parts, { tools }) : line("msg", it.at, it.from, parts, { mine, tools });
  m.row.dataset.id = m.id;
  R.msgs.set(m.id, m);
  ctx.place(m.row);
  for (const op of R.pending.get(m.id) || []) apply(R, m, op, ctx);
  R.pending.delete(m.id);
  return true;
}

// Burn messages: hidden behind "tap to reveal". Revealing tells the server you've read it (it destroys the ciphertext
// once everyone it was for has) and starts a countdown; then the text, attachments and decrypted copies are wiped from
// this page. No reactions, replies or edits on them. The sender sees their own until it's destroyed for everyone.
function showBurn(R, m, it, kind, mine, ctx) {
  const secs = m.payload.burn;
  const content = () => {
    const body = el("span", { cls: "body" });
    m.body = body;
    setText(m, m.payload.text, ctx.me, kind === "me" ? it.from : null);
    const parts = [body];
    if (kind === "file") { m.files = el("div", { cls: "att-list" }); for (const f of m.payload.files) m.files.append(fileView(R, f, Object.assign({}, ctx, { onGif: null }))); parts.push(m.files); }   // a burn message's GIF is never kept for re-sending
    return parts;
  };
  const tools = ctx.canDel(it.from) ? [el("button", { type: "button", title: "Delete for everyone", text: "del", onclick: () => ctx.onDelete(it.seq) })] : [];
  let slot;
  if (mine) {
    slot = el("div", { cls: "burn mine" }, [el("span", { cls: "burn-tag", text: "🔥 burns once read (" + secs + "s)" }), ...content()]);
  } else {
    const reveal = el("button", { type: "button", cls: "term-btn burn-reveal", text: "🔥 burn message — tap to reveal (visible for " + secs + "s, then destroyed)" });
    slot = el("div", { cls: "burn" }, [reveal]);
    reveal.addEventListener("click", () => {
      const timer = el("span", { cls: "burn-tag", text: "🔥 " + secs + "s" });
      clear(slot).append(timer, ...content());
      m.counting = true;                             // the server's delete (once all have read) waits for the countdown
      ctx.onBurnRead(it.seq);
      let left = secs;
      const tick = setInterval(() => {
        left -= 1;
        timer.textContent = "🔥 " + left + "s";
        if (left <= 0) { clearInterval(tick); burnOut(R, m); }
      }, 1000);
    }, { once: true });
  }
  m.row = line("msg burnline", it.at, it.from, [slot], { mine, tools });
  m.row.dataset.id = m.id;
  R.msgs.set(m.id, m);
  ctx.place(m.row);
  R.pending.delete(m.id);
  return true;
}

function burnOut(R, m) {
  m.payload = { k: "text", text: "" };
  // release the decrypted pictures/videos it showed
  if (m.row) m.row.querySelectorAll("img, video, audio").forEach((x) => { if (x.src.startsWith("blob:")) URL.revokeObjectURL(x.src); x.removeAttribute("src"); });
  if (m.row) { clear(m.row); m.row.append(el("span", { cls: "ts" }), el("span", { cls: "nick" }), el("div", { cls: "txt burned", text: "🔥 burned" })); }
  setTimeout(() => { if (m.row) m.row.remove(); R.msgs.delete(m.id); }, 2500);
}

// Returns true when the message stays for now (a burn message this person is still reading; its countdown removes it)
export function forget(R, seq) {
  for (const [id, m] of R.msgs) {
    if (m.seq !== seq) continue;
    if (m.counting) return true;
    R.msgs.delete(id); m.row.remove();
  }
  return false;
}

// ------------------------------------------------------------------------------------------------ text, quotes
function setText(m, text, me, actor) {
  clear(m.body);
  if (actor) m.body.append(actor + " ");
  if (text) m.body.append(...richText(text, me));
  m.body.classList.toggle("jumbo", !actor && !!text && isJumbo(text));     // a message of just 1-3 emoji shows them big
  if (m.edited) m.body.append(el("span", { cls: "edited", text: " (edited)" }));
}

function quote(R, id) {
  const t = R.msgs.get(id);
  const snippet = t ? (t.payload.text || (t.payload.files ? "[" + t.payload.files.length + " attachment(s)]" : "")).split("\n")[0].slice(0, 80) : "an earlier message";
  return el("button", { type: "button", cls: "quote", title: "Show the message this replies to",
                        onclick: () => { const r = R.msgs.get(id); if (r) { r.row.scrollIntoView({ block: "center" }); r.row.classList.add("flash"); setTimeout(() => r.row.classList.remove("flash"), 1200); } } },
            emojify("↳ " + (t ? t.from + ": " : "") + snippet));
}

// ------------------------------------------------------------------------------------------------ reactions and edits
// The newest operation (by server order) for each person+emoji wins, so history loaded in any order ends the same.
function apply(R, m, op, ctx) {
  if (op.kind === "edit") {
    if (op.from !== m.from || op.seq <= (m.edited || 0)) return;          // only the author, newest edit wins
    m.edited = op.seq;
    m.payload = Object.assign({}, m.payload, { text: op.payload.text });
    setText(m, op.payload.text, ctx.me, (m.payload.k === "me") ? m.from : null);
    return;
  }
  const k = op.from + "|" + op.payload.emoji;
  const prev = m.ops.get(k);
  if (prev && prev.seq >= op.seq) return;
  m.ops.set(k, { seq: op.seq, on: op.payload.on, from: op.from, emoji: op.payload.emoji });
  renderChips(m, ctx);
}

function renderChips(m, ctx) {
  const by = new Map();
  for (const o of m.ops.values()) if (o.on) { if (!by.has(o.emoji)) by.set(o.emoji, []); by.get(o.emoji).push(o.from); }
  clear(m.chips);
  for (const [emoji, users] of by) {
    const mineOn = users.includes(ctx.me);
    m.chips.append(el("button", { type: "button", cls: "react-chip" + (mineOn ? " mine" : ""), title: users.join(", "),
      "aria-label": emoji + " from " + users.join(", "), onclick: () => ctx.onReact(m.id, emoji, !mineOn) }, [...emojify(emoji), " " + users.length]));
  }
}

export function myReaction(m, me, emoji) { const o = m.ops.get(me + "|" + emoji); return !!(o && o.on); }

// ------------------------------------------------------------------------------------------------ attachments
async function fetchOpen(R, ref) {
  const sealed = await downloadBlob(R.id, ref.blob, ref.size);
  return C.openFile(sealed, ref.key, ref.size, ref.sha3);
}
function urlFor(R, bytes, type) {
  const u = URL.createObjectURL(new Blob([bytes], { type }));
  R.urls.push(u);
  return u;
}
const INLINE_IMG = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif"];
const INLINE_VID = ["video/mp4", "video/webm"];
const GIF_INLINE_MAX = 16 * 1048576;            // bigger GIFs show their still preview; the viewer plays them

function fileView(R, f, ctx) {
  const label = safeName(f.name) + " · " + human(f.size);
  if ((f.kind === "image" || f.kind === "video") && f.thumb) {
    const img = el("img", { cls: "att-img", alt: (f.kind === "video" ? "Video: " : "Picture: ") + safeName(f.name) });
    const gif = f.kind === "image" && f.mime === "image/gif" && f.size <= GIF_INLINE_MAX;
    const btn = el("button", { type: "button", cls: "att-thumb" + (f.kind === "video" ? " video" : "") + (gif ? " gif" : ""), title: label, onclick: () => openViewer(R, f, ctx) }, [img]);
    let playing = false;
    fetchOpen(R, f.thumb).then((b) => {
      const t = C.sniff(b);
      if (INLINE_IMG.includes(t) && !playing) img.src = urlFor(R, b, t);
    }).catch(() => { img.alt = "[preview unavailable] " + label; });
    // GIFs play inline (the whole file, decrypted here), unless the system asks for reduced motion: then the still
    // preview stays and the viewer plays it.
    if (gif && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      fetchOpen(R, f).then((b) => {
        if (C.sniff(b) !== "image/gif") return;
        playing = true;
        img.src = urlFor(R, b, "image/gif");
        if (ctx.onGif) ctx.onGif(safeName(f.name), b);
      }).catch(() => { /* the still preview stays */ });
    }
    return el("div", { cls: "att" }, [btn, el("span", { cls: "att-cap", text: (gif ? "GIF · " : "") + label })]);
  }
  const what = f.kind === "image" ? "picture" : f.kind === "video" ? "video" : f.kind === "audio" ? "audio" : "file";
  return el("div", { cls: "att" }, el("button", { type: "button", cls: "term-btn att-file", text: "⬇ " + what + ": " + label,
    onclick: () => (f.kind === "file" ? save(R, f, ctx) : openViewer(R, f, ctx)) }));
}

async function save(R, f, ctx) {
  try {
    const bytes = await fetchOpen(R, f);
    // always as a download (octet-stream): a decrypted file is never rendered or run by this page
    const a = el("a", { href: urlFor(R, bytes, "application/octet-stream"), download: safeName(f.name) });
    document.body.append(a); a.click(); a.remove();
  } catch (e) { ctx.log("Couldn't open " + safeName(f.name) + ": " + e.message); }
}

async function openViewer(R, f, ctx) {
  let bytes;
  try { bytes = await fetchOpen(R, f); } catch (e) { return ctx.log("Couldn't open " + safeName(f.name) + ": " + e.message); }
  const t = C.sniff(bytes);
  const node = INLINE_IMG.includes(t) ? el("img", { cls: "viewer-media", src: urlFor(R, bytes, t), alt: safeName(f.name) })
    : INLINE_VID.includes(t) ? el("video", { cls: "viewer-media", src: urlFor(R, bytes, t), controls: true, playsinline: true })
    : f.kind === "audio" ? el("audio", { src: urlFor(R, bytes, f.mime.startsWith("audio/") ? f.mime : "audio/mpeg"), controls: true })
    : null;
  if (!node) return save(R, f, ctx);                     // not something this page shows safely: offer the file instead
  const v = await dialog(safeName(f.name), (b) => { b.append(node, el("p", { cls: "cap", text: human(f.size) + " · end-to-end encrypted" })); },
    [{ label: "Save", value: "save" }, { label: "Close", cls: "primary" }]);
  if (v === "save") save(R, f, ctx);
}
