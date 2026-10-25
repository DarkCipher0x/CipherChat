// CipherChat by DarkCipher Systems: the terminal. State, rooms, room keys, sending and the long-poll loop.
// Security rules this file keeps (docs/CHAT.md has the reasoning):
//   - nothing is shown as a message unless its hybrid signature verifies under a TRUSTED identity (trust.js);
//   - room keys are only accepted from trusted identities, and only handed to trusted identities;
//   - a room key that went to anyone this browser doesn't trust is replaced before the next message is sent;
//   - keys live in this tab's memory only; locking (button, /lock, 15 minutes idle) reloads the page, which wipes them.
import * as C from "./crypto.js";
import { api, poll, setAsk, SELFTEST } from "./api.js";
import * as G from "./gate.js";
import { evaluate } from "./trust.js";
import { el, clear, line, dialog, ago } from "./term.js";
import * as M from "./messages.js";
import * as A from "./attach.js";
import { Outbox } from "./outbox.js";
import { QUICK, picker } from "./emoji.js";
import * as Gif from "./gifs.js";
import { CallEngine } from "./call.js";
import { newDeviceId, webHost } from "./callcrypto.js";
import * as CallUI from "./callui.js";

const $ = (id) => document.getElementById(id);
const IDLE_LOCK_MS = 15 * 60 * 1000;
const ROTATE_AFTER_S = 7 * 86400;               // room keys older than this are replaced before the next message
const TITLE = document.title;

const S = { st: null, me: null, people: new Map(), ownerProblem: "", rooms: new Map(), cur: null, lastSeq: 0, rev: 0,
            online: false, tests: 0, lastActive: Date.now(), polling: false, calls: null, sig: 0 };

// ---------------------------------------------------------------------------------------------- boot and unlock
const bootEl = $("boot");
function write(text, cls) { bootEl.append(cls ? el("span", { cls, text }) : text); }

// "Confirm it's you" for sensitive chat actions after the gate (certify, revoke, passphrase change): the chat's own
// terminal dialog, so the request never waits on a prompt that someone can't see.
setAsk((errText) => dialog("Confirm it's you", (b) => {
  const input = el("input", { cls: "term-field code-field", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6,
                              placeholder: "123456", "aria-label": "Authenticator code" });
  input.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); b.parentNode.querySelector(".primary").click(); } });
  b.append(el("p", { text: "This is a sensitive step (your keys, a certificate or a paired device). Enter the current 6-digit code from your authenticator app." }), input);
  if (errText) b.append(el("p", { cls: "gate-err", role: "alert", text: errText }));
  return { focus: input, value: () => input.value.replace(/\s+/g, "") };
}, [{ label: "Cancel" }, { label: "Confirm", cls: "primary", value: (a) => (/^\d{6}$/.test(a.value()) ? a.value() : false) }]));

// Nothing fails silently: an unexpected error lands on the screen the person is looking at.
window.addEventListener("unhandledrejection", (ev) => {
  const msg = "Unexpected error: " + ((ev.reason && ev.reason.message) || String(ev.reason));
  if (!$("gate").hidden) write("\n" + msg + "\n", "bad"); else fail(msg);
});

async function start() {
  try { S.tests = (await G.boot($("gate"), write)).length; } catch (e) { setBadge(false); return; }
  setBadge(true);
  let st;
  try { st = await api("state"); }
  catch (e) {
    write((e.data && e.data.denied ? "You don't have access to the chat. Ask the owner to give your account the Chat User role." : "Couldn't load the chat: " + e.message) + "\n", "bad");
    return;
  }
  S.st = st;
  if (!st.server_key_share) write("warning: the server key share is unavailable; identities can't be created or unlocked right now\n", "bad");
  let r = st.me.identity_fp ? await G.unlock($("gate"), st) : await G.setup($("gate"), st, false);
  if (!r.anchorFp && !st.me.owner) {
    S.st = await api("state");
    const pinned = await G.verifyOwner($("gate"), S.st, r);
    if (pinned) r.anchorFp = pinned;
  }
  S.me = { id: r.id, fp: r.fp, anchorFp: r.anchorFp };
  r.pass = null;
  if (r.master) r.master.fill(0);
  $("gate").hidden = true;
  $("lock-btn").hidden = false;
  enableInput(true);
  S.online = true;                              // the state just loaded; only a failed poll turns this off
  await applyState(await api("state"));
  S.lastSeq = S.st.last_seq;
  S.rev = S.st.dir_rev;
  const first = [...S.rooms.values()].sort(roomOrder)[0];
  if (first) await openRoom(first.id);
  else sys("No rooms yet. Create one with the + next to ROOMS, or type /help.");
  if (!S.me.anchorFp) warn("You haven't verified the owner yet, so nobody can be trusted. Type /repin when you're ready to compare safety numbers.");
  startCalls();
  watchIdle();
  pollLoop();
  $("input").focus();
}

function setBadge(ok) {
  const b = $("pq-badge");
  b.textContent = ok ? "PQ hybrid ✓" : "self-test failed";
  b.classList.toggle("bad", !ok);
  b.title = ok ? C.SUITE : "The crypto self-test failed in this browser";
}

// ---------------------------------------------------------------------------------------------- server state
async function refresh() { await applyState(await api("state")); }

async function applyState(st) {
  S.st = st;
  const t = await evaluate(st.directory, st.owner, S.me && S.me.anchorFp);
  S.people = t.people;
  if (t.ownerProblem && S.ownerProblem !== t.ownerProblem && S.me && S.me.anchorFp) warn("Trust problem: " + t.ownerProblem + ".");
  S.ownerProblem = t.ownerProblem;
  const seen = new Set();
  for (const info of st.rooms) {
    seen.add(info.id);
    let R = S.rooms.get(info.id);
    if (!R) {
      R = { id: info.id, info, keys: new Map(), hashes: new Map(), headers: new Map(), untrusted: new Set(), loaded: false,
            loading: null, queue: [], seqs: new Set(), oldest: Infinity, more: false, unread: 0, chain: Promise.resolve(),
            view: el("div", { cls: "room-view", hidden: true }), epochTried: new Set(), msgIds: new Set() };
      M.init(R);
      $("log").append(R.view);
      S.rooms.set(info.id, R);
    }
    R.info = info;
  }
  for (const [id, R] of S.rooms) if (!seen.has(id)) { R.view.remove(); S.rooms.delete(id); if (S.cur === id) S.cur = null; }
  renderSide();
  renderTopic();
  renderStatus();
  maybeAutoRotate();
}

function label(R) {
  if (R.info.kind === "dm") {
    const other = R.info.members.map((m) => m.user).find((u) => u !== S.st.me.user) || "(left)";
    return "@" + other;
  }
  return "#" + R.info.name;
}
const roomOrder = (a, b) => (a.info.kind === b.info.kind ? label(a).localeCompare(label(b)) : a.info.kind === "room" ? -1 : 1);
const trusted = (u) => { const p = S.people.get(u); return p && p.trust === "ok" && p.pub ? p : null; };

// ---------------------------------------------------------------------------------------------- sidebar, topic, status
function renderSide() {
  for (const [listId, kind] of [["room-list", "room"], ["dm-list", "dm"]]) {
    const ul = clear($(listId));
    [...S.rooms.values()].filter((R) => R.info.kind === kind).sort(roomOrder).forEach((R) => {
      ul.append(el("li", {}, el("button", { type: "button", cls: "room-item", "aria-current": S.cur === R.id ? "true" : "false",
        onclick: () => { openRoom(R.id); $("side").classList.remove("open"); } }, [
        el("span", { cls: "sig", text: kind === "dm" ? "@" : "#" }), el("span", { cls: "name", text: label(R).slice(1) }),
        el("span", { cls: "unread", text: R.unread ? String(R.unread) : "" })])));
    });
  }
  $("new-room").hidden = !S.st.me.can_create;
  const box = clear($("people"));
  for (const p of [...S.people.values()].sort((a, b) => a.user.localeCompare(b.user))) {
    const tag = { ok: ["ok", "verified"], pending: ["wait", "pending"], none: ["wait", "no keys"], bad: ["bad", "untrusted"] }[p.trust];
    box.append(el("button", { type: "button", cls: "room-item member-row", title: p.why, onclick: () => personDialog(p.user) }, [
      el("span", { cls: "who", text: p.user + (p.owner ? " *" : "") + (p.user === S.st.me.user ? " (you)" : "") }),
      p.addon ? el("span", { cls: "addon-tag", text: "add-on", title: "A program, not a person (the owner manages add-ons)" }) : null,
      el("span", { cls: "trust " + tag[0], text: tag[1] })]));
  }
  const total = [...S.rooms.values()].reduce((n, R) => n + R.unread, 0);
  document.title = (total ? "(" + total + ") " : "") + TITLE;
}

function renderTopic() {
  const box = clear($("topic"));
  const R = S.rooms.get(S.cur);
  if (!R) { box.append(el("span", { cls: "topic", text: "no room selected" })); return; }
  const i = R.info;
  const holders = i.epoch_recipients.length;
  const keyTxt = i.epoch ? "key #" + i.epoch + " · " + holders + "/" + i.members.length + " hold it · " + ago(i.epoch_at) + " old" : "no key yet";
  box.append(el("span", { cls: "room", text: label(R) }), el("span", { cls: "topic", text: i.topic || "" }),
    el("span", { cls: "key", title: "The room's current key (epoch). Every member it was made for is listed in its signed header.", text: keyTxt + (i.needs_rotation ? " · renewal due" : "") }),
    el("button", { type: "button", cls: "term-btn", text: "voice", title: "Voice call (end-to-end encrypted, post-quantum)", onclick: () => startCall(R, "audio") }),
    el("button", { type: "button", cls: "term-btn", text: "video", title: "Video call (end-to-end encrypted, post-quantum)", onclick: () => startCall(R, "video") }),
    el("button", { type: "button", cls: "term-btn", text: "members", onclick: () => membersDialog(R) }),
    i.kind === "room" && (i.my_role === "admin" || S.st.me.owner) ? el("button", { type: "button", cls: "term-btn", text: "settings", onclick: () => settingsDialog(R) }) : null);
  $("prompt-label").textContent = "";
  $("prompt-label").append(el("span", { cls: "user", text: S.st.me.user }), el("span", { cls: "host", text: "@cipherchat:" }), label(R) + "$");
}

function renderStatus() {
  const me = S.st && S.people.get(S.st.me.user);
  clear($("status")).append(
    el("span", { cls: S.online ? "on" : "off", text: S.online ? "● online" : "○ connecting" }),
    el("span", { cls: "acc", text: "ML-KEM-1024+X25519 · ML-DSA-87+Ed25519 · AES-256-GCM" }),
    el("span", { cls: "wide", text: "self-test " + S.tests + "/" + S.tests }),
    S.me ? el("span", { cls: "id", text: "id " + S.me.fp.slice(0, 16) + " " + (me && me.trust === "ok" ? "verified" : S.st.me.certified ? "certified" : "awaiting certification") }) : null,
    el("span", { cls: "wide", text: "auto-lock 15m" }),
    el("button", { type: "button", cls: "size-btn", title: "Text size (also /size)", "aria-label": "Text size " + textSize() + "%",
                   text: "Aa " + textSize() + "%", onclick: (ev) => sizeMenu(ev.currentTarget) }));
}

// ---------------------------------------------------------------------------------------------- log lines
function view() { const R = S.rooms.get(S.cur); return R ? R.view : $("log"); }
function scrollDown(force) {
  const log = $("log");
  if (force || log.scrollHeight - log.scrollTop - log.clientHeight < 120) log.scrollTop = log.scrollHeight;
}
function local(kind, text, R) { (R ? R.view : view()).append(line(kind, Date.now() / 1000, kind === "err" ? "!!" : "--", text)); scrollDown(true); }
const sys = (t, R) => local("sys", t, R);
const warn = (t, R) => local("warn", t, R);
const fail = (t, R) => local("err", t, R);
const ok = (t, R) => local("ok", t, R);

function place(R, row, seq, older) {
  row.dataset.seq = seq;
  if (older) {
    const firstSeq = [...R.view.children].find((n) => n.dataset && n.dataset.seq);
    R.view.insertBefore(row, firstSeq || R.view.firstChild);
  } else R.view.insertBefore(row, R.view.querySelector(".pending-out"));     // above your messages still on their way
}

// ---------------------------------------------------------------------------------------------- rooms
async function openRoom(id) {
  const R = S.rooms.get(id);
  if (!R) return;
  for (const x of S.rooms.values()) x.view.hidden = x.id !== id;
  if (S.cur !== id) { S.files = []; S.reply = null; S.edit = null; renderBars(); }   // attachments belong to one room
  S.cur = id;
  R.unread = 0;
  renderSide();
  renderTopic();
  if (!R.loaded && !R.loading) R.loading = loadRoom(R);
  await R.loading;
  scrollDown(true);
  maybeAutoRotate();
}

async function loadRoom(R) {
  try {
    await loadEpochs(R);
    const res = await api("rooms/" + R.id + "/items");
    R.more = res.more;
    const more = el("button", { type: "button", cls: "term-btn log-more", text: "load older messages", hidden: !res.more, onclick: () => loadOlder(R, more) });
    R.view.prepend(more);
    R.moreBtn = more;
    for (const it of res.items) await processItem(R, it, false, false);
    R.loaded = true;
    const q = R.queue; R.queue = [];
    for (const it of q) await processItem(R, it, true, false);
    if (!res.items.length) sys("Nothing here yet. Messages are end-to-end encrypted with this room's key; the server only stores ciphertext.", R);
  } catch (e) {
    fail("Couldn't load this room: " + e.message, R);
  } finally { R.loading = null; }
}

async function loadOlder(R, btn) {
  btn.disabled = true;
  try {
    const res = await api("rooms/" + R.id + "/items?before=" + R.oldest);
    const top = $("log").scrollHeight - $("log").scrollTop;
    for (const it of res.items.slice().reverse()) await processItem(R, it, false, true);
    btn.hidden = !res.more;
    $("log").scrollTop = $("log").scrollHeight - top;
  } catch (e) { fail("Couldn't load older messages: " + e.message, R); }
  btn.disabled = false;
}

async function loadEpochs(R) {
  const res = await api("rooms/" + R.id + "/epochs");
  for (const it of res.items) await openEpochItem(R, it, false);
}

// Accept a room key only if a trusted identity signed it, it was made for MY current identity, and its commitment
// matches. Note anyone it went to whom this browser doesn't trust: that key won't be used to send.
async function openEpochItem(R, it, announce) {
  if (R.keys.has(it.epoch)) return true;
  const signer = trusted(it.from);
  if (!signer) { if (announce) warn("Ignored room key #" + it.epoch + " from " + it.from + ": that identity isn't verified.", R); return false; }
  if (!it.body.w) return false;
  try {
    const { key, header, raw } = await C.openEpoch(S.me.id, S.me.fp, R.id, it, signer.pub);
    R.keys.set(it.epoch, key);
    R.hashes.set(it.epoch, C.headerHash(raw));
    R.headers.set(it.epoch, header);
    const odd = header.recipients.filter((r) => { const p = trusted(r.u); return !p || p.fp !== r.fp; });
    if (odd.length) {
      R.untrusted.add(it.epoch);
      warn("Room key #" + it.epoch + " was also given to identities you can't verify: " + odd.map((r) => r.u).join(", ") + ". It will be replaced before you send.", R);
    }
    const prev = R.hashes.get(it.epoch - 1);
    if (it.epoch > 1 && prev && header.prev !== prev) warn("Room key #" + it.epoch + " doesn't follow on from key #" + (it.epoch - 1) + " (key history was altered).", R);
    return true;
  } catch (e) {
    if (announce) fail("Room key #" + it.epoch + " from " + it.from + " was refused: " + e.message, R);
    return false;
  }
}

function processItem(R, it, live, older) {
  R.chain = R.chain.then(() => handle(R, it, live, older)).catch((e) => fail("Internal error: " + e.message, R));
  return R.chain;
}

async function handle(R, it, live, older) {
  if (R.seqs.has(it.seq)) return;
  R.seqs.add(it.seq);
  R.oldest = Math.min(R.oldest, it.seq);
  if (it.kind === "msg") {
    let key = R.keys.get(it.epoch);
    if (!key && !R.epochTried.has(it.epoch)) { R.epochTried.add(it.epoch); await loadEpochs(R).catch(() => {}); key = R.keys.get(it.epoch); }
    const who = trusted(it.from);
    if (!key) return place(R, line("warn", it.at, it.from, "[encrypted with room key #" + it.epoch + ", which wasn't made for you]"), it.seq, older);
    if (!who) return place(R, line("warn", it.at, it.from, "[hidden: " + it.from + "'s identity isn't verified]"), it.seq, older);
    try {
      const { header, payload } = await C.openMessage(it, key, who.pub);
      // Signed message ids are unique: a second copy is the server replaying an old message
      if (R.msgIds.has(header.id)) return place(R, line("warn", it.at, it.from, "[ignored: replayed copy of an earlier message]"), it.seq, older);
      R.msgIds.add(header.id);
      const me = S.st.me.user;
      if (it.from === me) OB.delivered(header.id);                       // its "sending" placeholder goes
      const shown = M.show(R, it, header, payload, {
        me, older,
        place: (row) => place(R, row, it.seq, older),
        canDel: (from) => from === me || (R.info.kind === "room" && R.info.my_role === "admin"),
        onReact: (id, emoji, on) => { try { enqueue(R, "react", emoji, { k: "react", text: "", target: id, emoji, on }); } catch (e) { fail(e.message, R); } },
        onReactMenu: (m, anchor) => reactMenu(R, m, anchor),
        onReply: (m) => { S.edit = null; S.reply = m; renderBars(); $("input").focus(); },
        onEdit: (m) => { S.reply = null; S.edit = m; $("input").value = m.payload.text; renderBars(); $("input").focus(); },
        onDelete: (seq) => redact(R, seq),
        onBurnRead: (seq) => api("rooms/" + R.id + "/burn", { seq }).catch((e) => fail("Couldn't tell the server to burn it: " + e.message, R)),
        onGif: (name, bytes) => Gif.remember(name, bytes),
        log: (t) => fail(t, R),
      });
      if (shown && live && S.cur !== R.id) { R.unread++; renderSide(); }
      if (shown && live && S.cur === R.id) scrollDown(it.from === me);
    } catch (e) {
      place(R, line("err", it.at, it.from, "[refused: " + e.message + "]"), it.seq, older);
    }
  } else if (it.kind === "epoch") {
    const got = await openEpochItem(R, it, live);
    const h = R.headers.get(it.epoch);
    place(R, line("sys", it.at, "--", got ? "new room key #" + it.epoch + " from " + it.from + " for " + h.recipients.map((r) => r.u).join(", ") + " (signed, ML-KEM-1024 + X25519)"
                                            : "room key #" + it.epoch + " from " + it.from + (it.body.w ? " (not accepted)" : " (not for you)")), it.seq, older);
  } else if (it.kind === "event") {
    place(R, line("srv", it.at, "server", describe(it.body)), it.seq, older);
  } else if (it.kind === "redact") {
    if (!M.forget(R, Number(it.body.target))) {
      const target = R.view.querySelector('[data-seq="' + Number(it.body.target) + '"]');
      if (target) target.remove();
    }
  }
  if (live && S.cur === R.id) scrollDown(false);
}

function describe(b) {
  const list = (a) => (a && a.length ? a.join(", ") : "");
  if (b.e === "created") return b.by + " created " + (b.name ? "#" + b.name : "this conversation") + (b.members ? " with " + list(b.members) : "");
  if (b.e === "members") return [b.add && b.add.length ? b.by + " added " + list(b.add) : "", b.remove && b.remove.length ? b.by + " removed " + list(b.remove) : "",
    b.admin && b.admin.length ? b.by + " made " + list(b.admin) + " admin" : "", b.member && b.member.length ? b.by + " made " + list(b.member) + " a member" : ""].filter(Boolean).join("; ");
  if (b.e === "updated") return b.by + " changed " + Object.keys(b).filter((k) => !["e", "by"].includes(k)).map((k) => k.replace("_", " ") + " to " + JSON.stringify(b[k])).join(", ");
  if (b.e === "left") return b.by + " left";
  if (b.e === "call") return b.by + " started a " + (b.media === "video" ? "video" : "voice") + " call";
  return b.by + ": " + b.e;
}

// ---------------------------------------------------------------------------------------------- keys and sending
async function rotate(R, reason) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const i = R.info;
    const recips = i.eligible.map((u) => {
      const p = trusted(u);
      if (!p) throw new Error("Can't give " + u + " the room key: " + ((S.people.get(u) || {}).why || "no verified identity") + ".");
      return { u, fp: p.fp, pub: p.pub };
    });
    if (!recips.some((r) => r.u === S.st.me.user)) throw new Error("Your identity isn't certified yet, so you can't hold this room's key.");
    const { pkg, key } = await C.buildEpoch(S.me.id, S.me.fp, R.id, i.epoch + 1, recips, R.hashes.get(i.epoch) || "");
    try {
      const res = await api("rooms/" + R.id + "/epoch", { pkg });
      R.keys.set(res.epoch, key);
      R.hashes.set(res.epoch, C.headerHash(C.unb64(pkg.h)));
      R.headers.set(res.epoch, JSON.parse(new TextDecoder().decode(C.unb64(pkg.h))));
      if (reason) sys("Made room key #" + res.epoch + " for " + recips.map((r) => r.u).join(", ") + " (" + reason + ").", R);
      await refresh();
      return key;
    } catch (e) {
      if (!(e.data && e.data.stale)) throw e;
      await refresh();
      if (!R.info.needs_rotation && R.keys.has(R.info.epoch)) return R.keys.get(R.info.epoch);
    }
  }
  throw new Error("The room kept changing while making a new key. Try again.");
}

async function keyFor(R) {
  const i = R.info;
  if (!S.me.anchorFp) throw new Error("Verify the owner first (/repin).");
  if (!i.needs_rotation && i.epoch && !R.keys.has(i.epoch)) await loadEpochs(R);
  const stale = i.epoch && Date.now() / 1000 - i.epoch_at > ROTATE_AFTER_S;
  if (i.needs_rotation || !i.epoch || !R.keys.has(i.epoch) || R.untrusted.has(i.epoch) || stale) {
    const why = !i.epoch ? "first key" : i.needs_rotation ? "members changed" : R.untrusted.has(i.epoch) ? "replacing a key given to unverified identities" : stale ? "weekly renewal" : "you didn't hold the current key";
    return rotate(R, why);
  }
  return R.keys.get(i.epoch);
}

// Admins renew keys as soon as members change, so newcomers can read without waiting for someone to speak.
let autoBusy = false;
async function maybeAutoRotate() {
  const R = S.rooms.get(S.cur);
  if (!R || autoBusy || !S.me || !S.me.anchorFp || !R.info.needs_rotation) return;
  const admin = R.info.kind === "dm" || R.info.my_role === "admin";
  if (!admin || !R.info.eligible.includes(S.st.me.user) || !R.info.eligible.every((u) => trusted(u))) return;
  autoBusy = true;
  try { await rotate(R, "members changed"); } catch (e) { /* the next send retries and reports */ }
  autoBusy = false;
}

// ---------------------------------------------------------------------------------------------- the outbox (outbox.js)
// Every message kind (text, me, file, react, edit) goes through the outbox: signed and encrypted under the room's current
// key, sent in order, and kept and retried through dropped connections until the server has it.
const OB = new Outbox({
  seal: async (R, payload) => {
    if (C.utf8(C.canon(payload)).length > C.MAX_TEXT_BYTES) throw new Error("That message is too long (" + C.MAX_TEXT_BYTES + " bytes at most).");
    const key = await keyFor(R);
    return C.sealMessage(S.me.id, S.me.fp, R.id, R.info.epoch, key, payload);
  },
  send: (R, msg, blobs, burn) => api("rooms/" + R.id + "/send", { msg, blobs, burn }),
  upload: async (R, item, status) => { const up = await A.uploadAll(R.id, [item], status); return { file: up.files[0], blobs: up.blobs }; },
  refresh: () => refresh(),
  msgId: (msg) => JSON.parse(new TextDecoder().decode(C.unb64(msg.h))).id,
  changed: (o) => renderPending(o),
  gone: (o) => { if (o.row) o.row.remove(); o.row = null; },
});

function enqueue(R, kind, preview, payload, files) {
  if (C.utf8(C.canon(payload)).length > C.MAX_TEXT_BYTES) throw new Error("That message is too long (" + C.MAX_TEXT_BYTES + " bytes at most).");
  if (!S.me || !S.me.anchorFp) throw new Error("Verify the owner first.");
  const o = OB.add(R, kind, preview, payload, files);
  if (o.visible) renderPending(o);
  return o;
}

// A message of yours still on its way: shown at the end of the room until the real one arrives
function renderPending(o) {
  if (!o.visible) return;
  const status = o.state === "queued" ? "⏳ queued · sends when you're back online" + (o.attempts && o.note ? " (" + o.note + ")" : "")
               : o.state === "sending" ? "↑ sending" + (o.note ? " · " + o.note : "") + "…"
               : o.state === "sent" ? "✓ sent" : "✕ not sent: " + (o.note || "refused");
  const row = line("msg", o.at || (o.at = Date.now() / 1000), S.st.me.user, [
    el("span", { cls: "pending-text", text: o.preview }), el("span", { cls: "pending-status", text: "  " + status }),
    o.state === "failed" ? el("button", { type: "button", cls: "term-btn", text: "retry", onclick: () => OB.retry(o) }) : null,
    o.state === "failed" || o.state === "queued" ? el("button", { type: "button", cls: "term-btn", text: "discard", onclick: () => OB.discard(o) }) : null,
  ], { mine: true });
  row.classList.add("pending-out");
  if (o.state === "failed") row.classList.add("failed");
  if (o.row && o.row.isConnected) o.row.replaceWith(row); else o.R.view.append(row);
  o.row = row;
  if (S.cur === o.R.id) scrollDown(true);
}

window.addEventListener("online", () => OB.wake());
window.addEventListener("beforeunload", (ev) => { if (OB.pending.length) { ev.preventDefault(); ev.returnValue = ""; } });

async function sendText(text, kind) {
  const R = S.rooms.get(S.cur);
  if (!R) return fail("Pick a room first.");
  const payload = { k: kind || "text", text };
  if (S.reply && S.reply.row.isConnected) payload.re = S.reply.id;
  if (S.burn) payload.burn = S.burn;
  enqueue(R, payload.k, text, payload);
}

// Burn toggle: off -> 10s -> 30s -> 1m -> 5m -> off. Applies to the next messages until switched off.
S.burn = 0;
const BURN_STEPS = [0, 10, 30, 60, 300];
function toggleBurn() {
  S.burn = BURN_STEPS[(BURN_STEPS.indexOf(S.burn) + 1) % BURN_STEPS.length];
  const b = $("burn-btn");
  b.classList.toggle("on", !!S.burn);
  b.textContent = S.burn ? "🔥" + (S.burn < 60 ? S.burn + "s" : S.burn / 60 + "m") : "🔥";
  b.setAttribute("aria-pressed", String(!!S.burn));
  b.title = S.burn ? "Burn messages on: destroyed " + S.burn + "s after being read (click to change)" : "Burn after reading (off)";
  renderBars();
}

// ---------------------------------------------------------------------------------------------- attachments, replies, edits
S.files = [];                  // prepared attachments waiting to be sent with the next message
S.preparing = 0;               // attachments still being read / thumbnailed: sending waits for them
S.reply = null; S.edit = null;

function renderBars() {
  const bar = clear($("compose-bar"));
  if (S.reply) bar.append(el("div", { cls: "bar-line" }, [el("span", { text: "↳ replying to " + S.reply.from + ": " + (S.reply.payload.text || "attachment").split("\n")[0].slice(0, 60) }),
    el("button", { type: "button", cls: "term-btn", text: "cancel", onclick: () => { S.reply = null; renderBars(); } })]));
  if (S.edit) bar.append(el("div", { cls: "bar-line" }, [el("span", { text: "✎ editing your message (Enter saves, Esc cancels)" }),
    el("button", { type: "button", cls: "term-btn", text: "cancel", onclick: () => { S.edit = null; $("input").value = ""; renderBars(); } })]));
  if (S.burn) bar.append(el("div", { cls: "bar-line burn-on" }, [el("span", { text: "🔥 burn after reading is on: your next messages are destroyed " + S.burn + "s after each recipient opens them" }),
    el("button", { type: "button", cls: "term-btn", text: "turn off", onclick: () => { S.burn = 300; toggleBurn(); } })]));
  if (S.files.length) {
    const chips = el("div", { cls: "bar-files" });
    S.files.forEach((f, i) => chips.append(el("span", { cls: "file-chip" }, [
      (f.kind === "image" ? "🖼 " : f.kind === "video" ? "🎬 " : "📎 ") + f.name + " (" + Math.max(1, Math.round(f.size / 1024)) + " KB)",
      el("button", { type: "button", "aria-label": "Remove " + f.name, text: "×", onclick: () => { S.files.splice(i, 1); renderBars(); } })])));
    bar.append(chips, el("div", { cls: "bar-status", id: "upload-status", text: "end-to-end encrypted before upload · Enter sends" }));
  }
  bar.hidden = !bar.childNodes.length;
}

async function addFiles(list) {
  const R = S.rooms.get(S.cur);
  if (!R) return fail("Pick a room first.");
  for (const file of Array.from(list)) {
    if (S.files.length + S.preparing >= A.MAX_FILES) { fail("Up to " + A.MAX_FILES + " attachments per message."); break; }
    S.preparing++;
    try {
      const f = await A.prepare(file);
      if (S.cur === R.id) S.files.push(f);          // read S.files after the await: a send or room change may have replaced it
      if (f.mime === "image/gif" && !S.burn) Gif.remember(f.name, f.bytes.slice());
    } catch (e) { fail(e.message, R); } finally { S.preparing--; }
    renderBars();
  }
  $("input").focus();
}

async function sendFiles(R, caption) {
  const items = S.files; S.files = [];
  renderBars();
  const payload = { k: "file", text: caption };
  if (S.reply && S.reply.row.isConnected) payload.re = S.reply.id;
  if (S.burn) payload.burn = S.burn;
  enqueue(R, "file", (caption ? caption + "\n" : "") + items.map((f) => "📎 " + f.name).join(", "), payload, items);
}

function reactMenu(R, m, anchor) {
  document.querySelectorAll(".emoji-pop").forEach((p) => p.remove());
  const me = S.st.me.user;
  const toggle = (emoji) => { try { enqueue(R, "react", emoji, { k: "react", text: "", target: m.id, emoji, on: !M.myReaction(m, me, emoji) }); } catch (e) { fail(e.message, R); } };
  const pop = el("div", { cls: "emoji-pop quick", role: "dialog", "aria-label": "React" }, QUICK.map((e) =>
    el("button", { type: "button", cls: "emoji-btn", text: e, "aria-label": "React " + e, onclick: () => { pop.remove(); toggle(e); } })));
  pop.append(el("button", { type: "button", cls: "emoji-btn more", text: "…", "aria-label": "More emoji",
                            onclick: () => { pop.remove(); picker(anchor, (e) => { document.querySelectorAll(".emoji-pop").forEach((p) => p.remove()); toggle(e); }); } }));
  const r = anchor.getBoundingClientRect();
  pop.style.bottom = (window.innerHeight - r.top + 6) + "px";
  document.body.append(pop);
  pop.style.left = Math.max(8, Math.min(window.innerWidth - pop.offsetWidth - 8, r.left - 120)) + "px";   // its real width: never off-screen
  const outside = (ev) => { if (!pop.contains(ev.target)) { pop.remove(); document.removeEventListener("pointerdown", outside, true); } };
  setTimeout(() => document.addEventListener("pointerdown", outside, true), 0);
}

function insertAtCursor(text) {
  const i = $("input");
  const s = i.selectionStart ?? i.value.length, e = i.selectionEnd ?? i.value.length;
  i.value = i.value.slice(0, s) + text + i.value.slice(e);
  i.selectionStart = i.selectionEnd = s + text.length;
  i.focus();
}

async function redact(R, seq) {
  if (!(await dialog("Delete message", (b) => b.append(el("p", { text: "Delete this message for everyone? The server removes the ciphertext." })),
    [{ label: "Cancel" }, { label: "Delete", cls: "danger", value: true }]))) return;
  try { await api("rooms/" + R.id + "/redact", { seq }); } catch (e) { fail(e.message, R); }
}

// ---------------------------------------------------------------------------------------------- polling
async function pollLoop() {
  if (S.polling) return;
  S.polling = true;
  let backoff = 1000;
  while (S.me) {
    try {
      const res = await poll(S.lastSeq, S.rev, S.sig);
      if (!S.online) { S.online = true; renderStatus(); OB.wake(); }
      backoff = 1000;
      if (res.dir_rev !== S.rev) { S.rev = res.dir_rev; await refresh(); }
      for (const it of res.items) {
        const R = S.rooms.get(it.room);
        if (!R) continue;
        if (!R.loaded) { if (R.loading) R.queue.push(it); else if (it.kind === "msg") { R.unread++; renderSide(); } continue; }
        await processItem(R, it, true, false);
      }
      S.lastSeq = Math.max(S.lastSeq, res.last_seq);
      if (res.signals && res.signals.length) {
        S.sig = Math.max(S.sig, ...res.signals.map((s) => s.sid));
        S.calls.handleSignals(res.signals);                // not awaited: a slow key unwrap never holds up messages
      }
    } catch (e) {
      if (e.data && e.data.denied) { fail("Your chat access was removed."); break; }
      if (S.online) { S.online = false; renderStatus(); }
      await new Promise((r) => setTimeout(r, backoff));
      backoff = Math.min(30000, backoff * 2);
    }
  }
  S.polling = false;
}

// ---------------------------------------------------------------------------------------------- calls (call.js)
function startCalls() {
  const dev = newDeviceId();
  const onEvent = CallUI.mount(null, {
    roomLabel: (id) => { const R = S.rooms.get(id); return R ? label(R) : "a room"; },
    notify: (kind, text) => (kind === "err" ? fail(text) : kind === "warn" ? warn(text) : sys(text)),
  });
  const verified = (u) => { const p = trusted(u); return p ? { pub: p.pub, fp: p.fp } : null; };
  S.calls = new CallEngine(Object.assign({ user: S.st.me.user, dev, api, trusted: verified, onEvent }, webHost(S.me.id, S.me.fp, dev, verified)));
  CallUI.bind(S.calls);
}

async function startCall(R, media) {
  if (!S.me.anchorFp) throw new Error("Verify the owner first (/repin): calls only go to verified people.");
  const people = R.info.members.map((m) => m.user).filter((u) => u !== S.st.me.user);
  try { await S.calls.start(R.id, media, people); }
  catch (e) { fail(e.message, R); }
}
// ---------------------------------------------------------------------------------------------- dialogs
function personDialog(user) {
  const p = S.people.get(user);
  const isOwner = S.st.me.owner, mine = user === S.st.me.user;
  dialog(user + (p.display_name ? " (" + p.display_name + ")" : ""), (b) => {
    b.append(el("p", { text: "Trust: " + p.trust + " — " + p.why }));
    if (p.fp) b.append(el("p", { cls: "fp", text: "Fingerprint " + C.fpGroups(p.fp) }));
    if (p.fp && !mine && S.me) {
      b.append(el("p", { text: "Safety number (compare out of band, never in this chat):" }),
        el("div", { cls: "safety" }, C.safetyNumber(S.me.fp, p.fp).split(" ").map((g) => el("span", { text: g }))));
    }
    if (isOwner && !mine && p.fp && p.trust === "pending")
      b.append(el("p", { cls: "cap", text: "Certify only after " + user + " has read you the same 60 digits on a call, in person or over a channel you already trust." }));
  }, [
    { label: "Close" },
    isOwner && !mine && p.fp && p.trust !== "ok" ? { label: "Certify", cls: "primary", value: "certify" } : null,
    isOwner && !mine && p.trust === "ok" ? { label: "Revoke", cls: "danger", value: "revoke" } : null,
    !mine && p.fp ? { label: "Message", value: "dm" } : null,
  ].filter(Boolean)).then(async (v) => {
    try {
      if (v === "certify") {
        const cert = await C.makeCert(S.me.id, S.me.fp, user, p.fp, Date.now());
        await api("certify", { user, cert });
        ok("Certified " + user + " (" + C.fpGroups(p.fp).slice(0, 19) + "…).");
        await refresh();
      } else if (v === "revoke") {
        await api("revoke", { user });
        warn("Revoked " + user + "'s certificate. Rooms they're in get new keys without them.");
        await refresh();
      } else if (v === "dm") await openDm(user);
    } catch (e) { fail(e.message); }
  });
}

function pickList(names, checked) {
  const ul = el("ul", { cls: "pick" });
  const boxes = names.map((n) => {
    const p = S.people.get(n) || {};
    const cb = el("input", { type: "checkbox", value: n, checked: checked && checked.includes(n) });
    ul.append(el("li", {}, el("label", {}, [cb, el("span", { text: n }), el("span", { cls: "trust " + (p.trust === "ok" ? "ok" : "wait"), text: p.trust === "ok" ? "verified" : p.trust || "" })])));
    return cb;
  });
  return { ul, picked: () => boxes.filter((b) => b.checked).map((b) => b.value) };
}

async function newRoomDialog() {
  const others = [...S.people.keys()].filter((u) => u !== S.st.me.user).sort();
  const v = await dialog("New private room", (b) => {
    b.append(el("p", { cls: "cap", text: "Only the people you add can see this room or read it: the room key is made for them alone, and you can add or remove people later (/invite, /kick)." }));
    const name = el("input", { cls: "term-field", maxlength: 32, placeholder: "dev-ops", spellcheck: "false", autocomplete: "off" });
    const topic = el("input", { cls: "term-field", maxlength: 200, placeholder: "optional", autocomplete: "off" });
    const keep = el("select", { cls: "term-field" }, S.st.limits.retention.map((d) => el("option", { value: d, text: d ? "delete messages after " + d + " day" + (d > 1 ? "s" : "") : "keep messages until deleted" })));
    const pick = pickList(others);
    b.append(el("span", { cls: "gate-label", text: "Name" }), name, el("span", { cls: "gate-label", text: "Topic" }), topic,
      el("span", { cls: "gate-label", text: "History" }), keep, el("span", { cls: "gate-label", text: "Members" }), pick.ul,
      el("p", { cls: "cap", text: "Room names, topics and member lists are visible to the server. Messages aren't." }));
    return { focus: name, value: () => ({ name: name.value.trim().replace(/^#/, ""), topic: topic.value, retention_days: Number(keep.value), members: pick.picked() }) };
  }, [{ label: "Cancel" }, { label: "Create", cls: "primary", value: (a) => a.value() }]);
  if (!v) return;
  try { const r = await api("rooms", v); await refresh(); await openRoom(r.id); } catch (e) { fail(e.message); }
}

async function newDmDialog() {
  const others = [...S.people.keys()].filter((u) => u !== S.st.me.user).sort();
  const v = await dialog("Direct message", (b) => {
    const sel = el("select", { cls: "term-field" }, others.map((u) => el("option", { value: u, text: u + " (" + S.people.get(u).trust + ")" })));
    b.append(el("span", { cls: "gate-label", text: "With" }), sel);
    return { focus: sel, value: () => sel.value };
  }, [{ label: "Cancel" }, { label: "Open", cls: "primary", value: (a) => a.value() }]);
  if (v) await openDm(v);
}
async function openDm(user) {
  try { const r = await api("dm", { user }); await refresh(); await openRoom(r.id); } catch (e) { fail(e.message); }
}

async function membersDialog(R) {
  const i = R.info;
  const admin = i.kind === "room" && (i.my_role === "admin" || S.st.me.owner);
  const current = i.members.map((m) => m.user);
  const v = await dialog("Members of " + label(R), (b) => {
    for (const m of i.members) {
      const p = S.people.get(m.user) || { trust: "none" };
      b.append(el("div", { cls: "member-row" }, [el("span", { cls: "who", text: m.user + (m.role === "admin" ? " (admin)" : "") }),
        el("span", { cls: "trust " + (i.epoch_recipients.includes(m.user) ? "ok" : "wait"), text: i.epoch_recipients.includes(m.user) ? "holds key" : "no key" }),
        el("span", { cls: "trust " + (p.trust === "ok" ? "ok" : "wait"), text: p.trust })]));
    }
    if (!admin) return {};
    const add = pickList([...S.people.keys()].filter((u) => !current.includes(u)).sort());
    const rem = pickList(current.filter((u) => u !== S.st.me.user));
    b.append(el("span", { cls: "gate-label", text: "Add" }), add.ul, el("span", { cls: "gate-label", text: "Remove" }), rem.ul,
      el("p", { cls: "cap", text: "Any change gives the room a new key: removed members can't read anything sent afterwards." }));
    return { value: () => ({ add: add.picked(), remove: rem.picked() }) };
  }, admin ? [{ label: "Close" }, { label: "Apply", cls: "primary", value: (a) => a.value() }] : [{ label: "Close" }]);
  if (!v || (!v.add.length && !v.remove.length)) return;
  try { await api("rooms/" + R.id + "/members", v); await refresh(); await maybeAutoRotate(); } catch (e) { fail(e.message, R); }
}

async function settingsDialog(R) {
  const i = R.info;
  const v = await dialog("Settings for " + label(R), (b) => {
    const name = el("input", { cls: "term-field", maxlength: 32, value: i.name });
    const topic = el("input", { cls: "term-field", maxlength: 200, value: i.topic });
    const keep = el("select", { cls: "term-field" }, S.st.limits.retention.map((d) => el("option", { value: d, selected: d === i.retention_days, text: d ? d + " days" : "until deleted" })));
    b.append(el("span", { cls: "gate-label", text: "Name" }), name, el("span", { cls: "gate-label", text: "Topic" }), topic, el("span", { cls: "gate-label", text: "Keep messages" }), keep);
    return { value: () => ({ name: name.value.trim().replace(/^#/, ""), topic: topic.value, retention_days: Number(keep.value) }) };
  }, [{ label: "Delete room", cls: "danger", value: "delete" }, { label: "Cancel" }, { label: "Save", cls: "primary", value: (a) => a.value() }]);
  try {
    if (v === "delete") {
      if (await dialog("Delete " + label(R), (b) => b.append(el("p", { text: "Delete the room and every message in it for everyone? This can't be undone." })),
        [{ label: "Cancel" }, { label: "Delete", cls: "danger", value: true }])) { await api("rooms/" + R.id + "/delete", {}); await refresh(); }
    } else if (v) { await api("rooms/" + R.id + "/update", v); await refresh(); }
  } catch (e) { fail(e.message, R); }
}

// ---------------------------------------------------------------------------------------------- commands
const HELP = [
  "/help                    this list",
  "/join #room | @user      switch room or open a direct message",
  "/new name [user ...]     create a room",
  "/me does something       action line",
  "/topic text              set the topic (admins)",
  "/invite user ...         add members (admins)        /kick user ...   remove members",
  "/members                 who is here and who holds the key",
  "/call  /video            a voice or video call with this room (end-to-end encrypted, post-quantum)",
  "/hangup                  leave the call",
  "/rotate                  make a new room key now",
  "/verify user             safety number; the owner can certify from there",
  "/fp                      your identity fingerprint",
  "/repin                   verify the owner again (after the owner reset their identity)",
  "/passphrase              change your chat passphrase",
  "/reset-identity          start a new identity (old keys stop working)",
  "/leave                   leave this room",
  "/clear                   clear the screen (messages stay on the server)",
  "/lock                    wipe keys from memory and lock",
  "/size [+|-|0|percent]    the terminal's text size (also the Aa button, bottom right)",
  "/selftest                open the crypto self-test page",
  "/devices                 your paired devices (remove one here)",
  "/pair [name]             pair a CipherChat app (needs a fresh code)",
  "/addons                  add-ons and connectors (owner): create, scopes, rotate, disable, remove",
  "Enter sends, Shift+Enter is a new line. ```fences``` make code blocks.",
  "+ attaches files, pictures, videos and GIFs (or paste / drop them); ☺ inserts emoji; GIF sends a GIF again or picks one.",
  "Hover a message to react, reply, edit (your own) or delete. Esc cancels a reply or edit.",
  "Attachments are encrypted in this browser before upload; the server only stores ciphertext.",
];

async function command(raw) {
  const [cmd, ...args] = raw.trim().split(/\s+/);
  const R = S.rooms.get(S.cur);
  const rest = raw.trim().slice(cmd.length).trim();
  const need = () => { if (!R) throw new Error("Pick a room first."); return R; };
  switch (cmd.toLowerCase()) {
    case "/help": HELP.forEach((h) => sys(h)); return;
    case "/me": if (rest) await sendText(rest, "me"); return;
    case "/join": {
      const t = args[0] || "";
      if (t.startsWith("@")) return openDm(t.slice(1));
      const f = [...S.rooms.values()].find((x) => x.info.kind === "room" && x.info.name === t.replace(/^#/, ""));
      return f ? openRoom(f.id) : fail("You're not in a room called " + t + ".");
    }
    case "/new": {
      const r = await api("rooms", { name: (args[0] || "").replace(/^#/, ""), members: args.slice(1), retention_days: 0 });
      await refresh(); return openRoom(r.id);
    }
    case "/topic": await api("rooms/" + need().id + "/update", { topic: rest }); return refresh();
    case "/invite": await api("rooms/" + need().id + "/members", { add: args }); await refresh(); return maybeAutoRotate();
    case "/kick": await api("rooms/" + need().id + "/members", { remove: args }); await refresh(); return maybeAutoRotate();
    case "/members": return membersDialog(need());
    case "/call": return startCall(need(), "audio");
    case "/video": return startCall(need(), "video");
    case "/hangup": return S.calls && S.calls.hangup();
    case "/rotate": await rotate(need(), "by request"); return;
    case "/verify": return S.people.has(args[0]) ? personDialog(args[0]) : fail("No chat user called " + args[0] + ".");
    case "/fp": sys("Your fingerprint: " + C.fpGroups(S.me.fp)); return;
    case "/leave":
      if (await dialog("Leave " + label(need()), (b) => b.append(el("p", { text: "Leave this room? You'll need to be added again to come back." })),
        [{ label: "Cancel" }, { label: "Leave", cls: "danger", value: true }])) { await api("rooms/" + R.id + "/leave", {}); await refresh(); }
      return;
    case "/clear": [...view().children].forEach((n) => { if (!n.classList.contains("log-more")) n.remove(); }); return;
    case "/lock": return lock();
    case "/size": {
      const a = (args[0] || "").replace("%", "");
      if (a === "+" || a === "-" || a === "0") return stepTextSize(a === "+" ? 1 : a === "-" ? -1 : 0);
      if (SIZES.includes(Number(a))) return setTextSize(Number(a));
      sys("Text size " + textSize() + "%. /size + or /size - steps it, /size 0 resets; sizes: " + SIZES.join(" ") + ".");
      return;
    }
    case "/selftest": window.open(SELFTEST, "_blank", "noopener"); return;
    case "/passphrase": return passphraseDialog();
    case "/repin": return repin();
    case "/reset-identity": return resetIdentity();
    case "/devices": return devicesDialog();
    case "/pair": return pairDevice(rest);
    case "/addons": return S.st.me.owner ? addonsDialog() : fail("Only the owner manages add-ons.");
    default: fail("Unknown command " + cmd + ". Type /help.");
  }
}

// --------------------------------------------------------------------------------------------- paired devices
// A CipherChat app signs in with a one-time device token (only its SHA-256 is kept on the server). The pairing code
// carries the server's origin and the token; it's shown once, here, and nowhere else.
async function devicesDialog() {
  const { devices } = await api("devices");
  const v = await dialog("Paired devices", (b) => {
    if (!devices.length) b.append(el("p", { text: "No devices paired. The CipherChat apps (Android, Windows) sign in with a pairing code from here." }));
    for (const d of devices) {
      b.append(el("div", { cls: "member-row" }, [el("span", { cls: "who", text: d.name + (d.this ? " (this device)" : "") }),
        el("span", { cls: "trust wait", text: "used " + ago(d.last_used) + ", ends " + new Date(d.expires * 1000).toLocaleDateString() }),
        el("button", { type: "button", cls: "term-btn danger", text: "remove", "aria-label": "Remove " + d.name,
                       onclick: (ev) => { ev.target.closest("dialog").close(); unpair(d); } })]));
    }
    return {};
  }, [{ label: "Close" }, { label: "Pair a device", cls: "primary", value: true }]);
  if (v) return pairDevice("");
}

async function unpair(d) {
  if (!(await dialog("Remove " + d.name, (b) => b.append(el("p", { text: "The device is signed out at once and its pairing code stops working. Pair it again to use it." })),
    [{ label: "Cancel" }, { label: "Remove", cls: "danger", value: true }]))) return;
  await api("devices/" + d.id + "/revoke", {});
  sys("Removed the pairing for " + d.name + ".");
}

async function pairDevice(name) {
  if (!name) {
    name = await dialog("Pair a device", (b) => {
      b.append(el("p", { text: "Give the device a name you'll recognise (say Pixel or Desktop PC). Pairing needs a fresh authenticator code." }));
      const i = el("input", { cls: "term-field", maxlength: 40, autocomplete: "off", value: "" });
      b.append(i);
      return { focus: i, value: () => i.value.trim() || "Device" };
    }, [{ label: "Cancel" }, { label: "Continue", cls: "primary", value: (a) => a.value() }]);
    if (!name) return;
  }
  const j = await api("devices", { name });
  const code = "cipherchat:pair/v1?server=" + encodeURIComponent(location.origin) + "&token=" + j.token;
  await dialog("Pairing code for " + j.name, (b) => {
    b.append(el("p", { text: "In the CipherChat app choose Pair with a code and paste this code. It's shown once; anyone who has it can sign in as you to the chat (nothing else), so don't send it in a chat or by email." }));
    const box = el("code", { cls: "pair-code", text: code });
    const copy = el("button", { type: "button", cls: "term-btn", text: "copy",
      onclick: () => navigator.clipboard && navigator.clipboard.writeText(code).then(() => { copy.textContent = "copied"; }) });
    b.append(box, copy, el("p", { cls: "cap", text: "The pairing ends after " + j.idle_days + " days unused, or on " + new Date(j.expires * 1000).toLocaleDateString() + ". Remove it any time with /devices." }));
    return {};
  }, [{ label: "Done", cls: "primary", value: true }]);
  sys("Paired " + j.name + ". Unused, the code stops working after " + j.idle_days + " days.");
}

// --------------------------------------------------------------------------------------------- add-ons (owner)
// Programs with an identity of their own (docs/ADDONS.md): bots and connectors such as CommandCentre. The connector
// code (server, add-on, 256-bit request key) is shown once; the add-on then makes its own post-quantum identity, which
// the owner certifies like a person's (/verify addon.name), and room admins add it to the rooms it should see.
const ADDON_SCOPES = { send: "send messages, reactions and edits", files: "upload and download attachments", dm: "start direct messages" };

async function addonsDialog() {
  const { addons } = await api("addons");
  const pick = await dialog("Add-ons", (b) => {
    b.append(el("p", { text: "Add-ons are programs (bots, connectors to your other systems) with their own post-quantum identity. They only see rooms they're added to, every request is signed, and everyone sees they're add-ons." }));
    if (!addons.length) b.append(el("p", { cls: "cap", text: "No add-ons yet." }));
    for (const a of addons) {
      const state = !a.enabled ? "disabled" : !a.identity_fp ? "waiting for its keys" : !a.certified ? "verify it: /verify " + a.user : "ready";
      b.append(el("div", { cls: "member-row addon-row" }, [
        el("span", { cls: "who", text: a.user + (a.display_name ? " · " + a.display_name : "") }),
        el("span", { cls: "trust " + (a.enabled && a.certified ? "ok" : "wait"), text: state }),
        el("span", { cls: "cap", text: "scopes: " + (a.scopes.join(", ") || "read only") + " · " + a.rooms + " room(s)" +
          (a.ip_allow.length ? " · from " + a.ip_allow.join(", ") : "") + " · last used " + (a.last_used ? ago(a.last_used) : "never") +
          " · ends " + new Date(a.expires * 1000).toLocaleDateString() }),
        el("span", { cls: "addon-actions" }, [
          el("button", { type: "button", cls: "term-btn", text: "edit", onclick: (ev) => { ev.target.closest("dialog").close(); addonEdit(a); } }),
          el("button", { type: "button", cls: "term-btn", text: "new key", onclick: (ev) => { ev.target.closest("dialog").close(); addonAct(a, "rotate"); } }),
          el("button", { type: "button", cls: "term-btn", text: a.enabled ? "disable" : "enable", onclick: (ev) => { ev.target.closest("dialog").close(); addonAct(a, a.enabled ? "disable" : "enable"); } }),
          el("button", { type: "button", cls: "term-btn danger", text: "remove", onclick: (ev) => { ev.target.closest("dialog").close(); addonAct(a, "delete"); } })]),
      ]));
    }
    return {};
  }, [{ label: "Close" }, { label: "New add-on", cls: "primary", value: true }]);
  if (pick) return addonEdit(null);
}

function addonForm(b, a) {
  const f = {};
  if (!a) {
    b.append(el("span", { cls: "gate-label", text: "Name (becomes addon.name; a-z, 0-9, -)" }));
    f.name = el("input", { cls: "term-field", maxlength: 26, autocomplete: "off", spellcheck: "false" });
    b.append(f.name, el("span", { cls: "gate-label", text: "Display name" }));
    f.display = el("input", { cls: "term-field", maxlength: 60, autocomplete: "off" });
    b.append(f.display);
  }
  b.append(el("span", { cls: "gate-label", text: "What it may do (it can always read the rooms it's in)" }));
  f.scopes = Object.entries(ADDON_SCOPES).map(([k, t]) => {
    const c = el("input", { type: "checkbox", checked: a ? a.scopes.includes(k) : k === "send" });
    b.append(el("label", { cls: "check-row" }, [c, " " + k + " — " + t]));
    return [k, c];
  });
  b.append(el("span", { cls: "gate-label", text: "Only from these addresses or networks (optional, comma separated)" }));
  f.ips = el("input", { cls: "term-field", maxlength: 600, autocomplete: "off", spellcheck: "false", value: a ? a.ip_allow.join(", ") : "" });
  b.append(f.ips, el("span", { cls: "gate-label", text: "Valid for (days, 1-730)" }));
  f.days = el("input", { cls: "term-field", type: "number", min: 1, max: 730, value: 365 });
  b.append(f.days, el("span", { cls: "gate-label", text: "Description (for you)" }));
  f.desc = el("input", { cls: "term-field", maxlength: 200, value: a ? a.description : "" });
  b.append(f.desc);
  return {
    focus: f.name || f.ips,
    value: () => {
      const out = { scopes: f.scopes.filter(([, c]) => c.checked).map(([k]) => k),
                    ip_allow: f.ips.value.split(",").map((s) => s.trim()).filter(Boolean),
                    days: Math.max(1, Math.min(730, parseInt(f.days.value, 10) || 365)), description: f.desc.value.trim() };
      if (f.name) { out.name = f.name.value.trim().toLowerCase(); out.display_name = f.display.value.trim(); }
      return out;
    },
  };
}

async function addonEdit(a) {
  const v = await dialog(a ? "Edit " + a.user : "New add-on", (b) => addonForm(b, a),
    [{ label: "Cancel" }, { label: a ? "Save" : "Create", cls: "primary", value: (x) => x.value() }]);
  if (!v) return;
  if (a) { await api("addons/" + a.user + "/update", v); ok(a.user + " updated."); return; }
  const j = await api("addons", v);
  await refresh();
  await showAddonCode(j.user, j.code, "Created " + j.user + ".");
}

async function addonAct(a, what) {
  const warn = { delete: "Remove " + a.user + "? It leaves every room (they get new keys without it) and its identity and key are deleted.",
                 rotate: "Make a new connector code for " + a.user + "? The current one stops working at once.",
                 disable: "Disable " + a.user + "? Its requests are refused until you enable it again." }[what];
  if (warn && !(await dialog(a.user, (b) => b.append(el("p", { text: warn })), [{ label: "Cancel" }, { label: what === "delete" ? "Remove" : "Continue", cls: what === "delete" ? "danger" : "primary", value: true }]))) return;
  const j = await api("addons/" + a.user + "/" + what, {});
  await refresh();
  if (j.code) return showAddonCode(a.user, j.code, "New key for " + a.user + ".");
  ok(a.user + ": " + { delete: "removed", disable: "disabled", enable: "enabled" }[what] + ".");
}

// The server's code says where and with which key; this client adds the owner's fingerprint from its OWN keys, so the
// add-on pins the trust anchor without having to believe the server about it.
function withOwnerFp(code) {
  const P = "ccaddon1.";
  const raw = code.slice(P.length).replace(/-/g, "+").replace(/_/g, "/");
  const j = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(raw + "=".repeat((4 - raw.length % 4) % 4)), (c) => c.charCodeAt(0))));
  if (!S.st.me.owner || !S.me || !/^[0-9a-f]{64}$/.test(S.me.fp)) throw new Error("Only the owner's unlocked chat can hand out connector codes.");
  j.a = S.me.fp;
  const bytes = new TextEncoder().encode(JSON.stringify(j));
  return P + btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function showAddonCode(user, serverCode, done) {
  const code = withOwnerFp(serverCode);
  await dialog("Connector code for " + user, (b) => {
    b.append(el("p", { text: "Put this in the add-on's configuration (it encrypts it at rest). It's shown once and it's the add-on's key: never paste it into a chat or an email." }));
    const box = el("code", { cls: "pair-code", text: code });
    const copy = el("button", { type: "button", cls: "term-btn", text: "copy",
      onclick: () => navigator.clipboard && navigator.clipboard.writeText(code).then(() => { copy.textContent = "copied"; }) });
    b.append(box, copy, el("p", { cls: "cap", text: "Next: start the add-on (it makes its own keys and prints its safety number), then /verify " + user + " to compare and certify it, and add it to rooms with /invite " + user + "." }));
    return {};
  }, [{ label: "Done", cls: "primary", value: true }]);
  ok(done);
}

function passwordDialog(title, labels, note) {
  return dialog(title, (b) => {
    if (note) b.append(el("p", { text: note }));
    const inputs = labels.map((l) => { const i = el("input", { cls: "term-field", type: "password", maxlength: 1024, autocomplete: "off" }); b.append(el("span", { cls: "gate-label", text: l }), i); return i; });
    return { focus: inputs[0], value: () => inputs.map((i) => i.value) };
  }, [{ label: "Cancel" }, { label: "OK", cls: "primary", value: (a) => a.value() }]);
}

async function passphraseDialog() {
  const v = await passwordDialog("Change chat passphrase", ["Current passphrase", "New passphrase", "New passphrase again"]);
  if (!v) return;
  if (v[1] !== v[2]) return fail("The new passphrases don't match.");
  try { sys("Re-sealing your keys…"); await G.changePassphrase(S.st, S.me, v[0], v[1]); ok("Passphrase changed."); }
  catch (e) { fail(e instanceof C.CryptoFail && e.message === "wrong passphrase" ? "The current passphrase isn't right." : e.message); }
}

async function repin() {
  const v = await passwordDialog("Verify the owner again", ["Your chat passphrase"], "You'll compare a new safety number with the owner.");
  if (!v) return;
  try {
    const b = await api("backup/fetch", {});
    const payload = await C.openBackup(S.st.me.user, v[0], C.unb64(b.pepper, 32), b.backup);
    S.st = await api("state");
    $("gate").hidden = false;
    clear($("boot"));
    const pinned = await G.verifyOwner($("gate"), S.st, { fp: S.me.fp, pass: v[0], payload });
    $("gate").hidden = true;
    if (pinned) { S.me.anchorFp = pinned; ok("Owner identity pinned."); await refresh(); }
  } catch (e) { $("gate").hidden = true; fail(e.message); }
}

async function resetIdentity() {
  if (!(await dialog("Reset your identity", (b) => b.append(el("p", { text: "This makes a brand-new identity. Your certificate ends, everyone has to see you verified again, and messages under your old keys become unreadable to you." + (S.st.me.owner ? " You're the owner: EVERY member's certificate ends and every member has to re-verify you." : "") })),
    [{ label: "Cancel" }, { label: "Reset", cls: "danger", value: true }]))) return;
  $("gate").hidden = false;
  clear($("boot"));
  try {
    const r = await G.setup($("gate"), S.st, true);
    r.pass = null;
    location.reload();
  } catch (e) { $("gate").hidden = true; fail(e.message); }
}

function lock() {
  const bye = S.calls && S.calls.call ? S.calls.hangup().catch(() => {}) : Promise.resolve();
  bye.finally(() => { S.me = null; location.reload(); });
}

// ---------------------------------------------------------------------------------------------- input and idle
function enableInput(on) { for (const id of ["input", "send", "attach-btn", "emoji-btn", "gif-btn", "burn-btn"]) $(id).disabled = !on; }

// ---------------------------------------------------------------------------------------------- text size
// The terminal's text size, for this browser only (a convenience: kept in localStorage, which may be unavailable).
const SIZES = [90, 100, 110, 125, 140, 160, 180, 200];
const SIZE_KEY = "cipherchat.textSize";
function textSize() { try { const n = Number(localStorage.getItem(SIZE_KEY)); return SIZES.includes(n) ? n : 100; } catch (e) { return 100; } }
function setTextSize(n) {
  if (!SIZES.includes(n)) return;
  document.documentElement.style.setProperty("--t-scale", String(n / 100));
  try { localStorage.setItem(SIZE_KEY, String(n)); } catch (e) { /* this visit only */ }
  renderStatus();
}
function stepTextSize(dir) {
  if (dir === 0) return setTextSize(100);
  const i = SIZES.indexOf(textSize()) + dir;
  if (i >= 0 && i < SIZES.length) setTextSize(SIZES[i]);
}
function sizeMenu(anchor) {
  document.querySelectorAll(".emoji-pop").forEach((p) => p.remove());
  const out = el("output", { text: textSize() + "%" });
  const step = (d) => { stepTextSize(d); out.textContent = textSize() + "%"; };
  const pop = el("div", { cls: "emoji-pop size-pop", role: "dialog", "aria-label": "Text size" }, [
    el("button", { type: "button", cls: "term-btn", text: "A−", "aria-label": "Smaller text", onclick: () => step(-1) }), out,
    el("button", { type: "button", cls: "term-btn", text: "A+", "aria-label": "Bigger text", onclick: () => step(1) }),
    el("button", { type: "button", cls: "term-btn", text: "reset", onclick: () => step(0) })]);
  const close = () => { pop.remove(); document.removeEventListener("pointerdown", outside, true); };
  const outside = (ev) => { if (!pop.contains(ev.target) && !ev.target.closest(".size-btn")) close(); };
  pop.addEventListener("keydown", (ev) => { if (ev.key === "Escape") close(); });
  document.addEventListener("pointerdown", outside, true);
  const r = anchor.getBoundingClientRect();
  pop.style.bottom = (window.innerHeight - r.top + 6) + "px";
  document.body.append(pop);
  pop.style.left = Math.max(8, Math.min(window.innerWidth - pop.offsetWidth - 8, r.right - pop.offsetWidth)) + "px";
  pop.querySelector("button").focus();
}
document.documentElement.style.setProperty("--t-scale", String(textSize() / 100));

function watchIdle() {
  const bump = () => { S.lastActive = Date.now(); };
  ["keydown", "pointerdown", "wheel", "touchstart"].forEach((t) => document.addEventListener(t, bump, { passive: true }));
  setInterval(() => {
    if (S.calls && S.calls.call) S.lastActive = Date.now();   // nobody is idle in a call
    if (S.me && Date.now() - S.lastActive > IDLE_LOCK_MS) lock();
  }, 15000);
}

$("prompt").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = $("input");
  const text = input.value;
  const R = S.rooms.get(S.cur);
  if (!S.me || (!text.trim() && !S.files.length && !S.preparing)) return;
  if (S.preparing) return fail("Still preparing " + S.preparing + " attachment(s): send again in a moment.", R);
  input.value = "";
  input.style.height = "";
  try {
    if (S.edit) {
      const target = S.edit;
      S.edit = null; renderBars();
      if (text.trim() && text !== target.payload.text) enqueue(R, "edit", text, { k: "edit", text, target: target.id });
    } else if (S.files.length) {
      await sendFiles(R, text);
    } else if (text.startsWith("/") && !text.startsWith("//")) await command(text);
    else await sendText(text.startsWith("//") ? text.slice(1) : text);
    S.reply = null; renderBars();
  } catch (e) {
    fail(e.message || String(e));
    if (!input.value) input.value = text;
  }
});
$("input").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); $("prompt").requestSubmit(); }
  if (ev.key === "Escape" && (S.edit || S.reply)) { if (S.edit) $("input").value = ""; S.edit = null; S.reply = null; renderBars(); }
});
// Pasted pictures (screenshots, GIFs from the clipboard) and dropped files become attachments
$("input").addEventListener("paste", (ev) => {
  const files = ev.clipboardData && ev.clipboardData.files;
  if (files && files.length) { ev.preventDefault(); addFiles(files); }
});
$("term").addEventListener("dragover", (ev) => { if (ev.dataTransfer && Array.from(ev.dataTransfer.types).includes("Files")) ev.preventDefault(); });
$("term").addEventListener("drop", (ev) => {
  if (ev.dataTransfer && ev.dataTransfer.files.length && S.me) { ev.preventDefault(); addFiles(ev.dataTransfer.files); }
});
$("attach-btn").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", (ev) => { addFiles(ev.target.files); ev.target.value = ""; });
$("emoji-btn").addEventListener("click", (ev) => picker(ev.currentTarget, insertAtCursor));
$("gif-btn").addEventListener("click", (ev) => Gif.picker(ev.currentTarget, (file) => addFiles([file]), () => $("gif-input").click()));
$("gif-input").addEventListener("change", (ev) => { addFiles(ev.target.files); ev.target.value = ""; });
$("burn-btn").addEventListener("click", toggleBurn);
$("input").addEventListener("input", (ev) => {
  const t = ev.target; t.style.height = "auto"; t.style.height = Math.min(180, t.scrollHeight) + "px";
});
$("lock-btn").addEventListener("click", lock);
$("new-room").addEventListener("click", newRoomDialog);
$("new-dm").addEventListener("click", newDmDialog);
$("side-toggle").addEventListener("click", () => {
  const open = $("side").classList.toggle("open");
  $("side-toggle").setAttribute("aria-expanded", String(open));
});

window.dcx.me().then(start, () => {});
