// CipherChat by DarkCipher Systems: the call screen (docs/CALLS.md). Renders what call.js reports and passes the
// person's choices back; no keys or signalling here. Built with createElement/textContent only (term.js rules).
import { el, clear } from "./term.js";
import { glitchIn } from "./glitch.js";

const QUICK = ["👍", "❤️", "😂", "🎉", "👏", "🔥"];
let E = null, host = null, screen = null, grid = null, top = null, bar = null, ringBox = null, tone = null;
const tiles = new Map();                          // "user|dev:slot" -> {box, video, name, badge}
let timer = null, ptt = false, pttDown = false, blurOn = false;

export function bind(engine) { E = engine; }

export function mount(engine, opts) {
  E = engine;
  host = opts;                                    // {roomLabel(id), notify(kind, text), onEnded?}
  screen = el("section", { cls: "call-screen", id: "call-screen", hidden: true, "aria-label": "Call" });
  top = el("header", { cls: "call-top" });
  grid = el("div", { cls: "call-grid" });
  bar = el("footer", { cls: "call-bar" });
  screen.append(top, grid, bar);
  document.body.append(screen);
  document.addEventListener("keydown", keys);
  document.addEventListener("keyup", (ev) => { if (ptt && ev.code === "Space" && pttDown) { pttDown = false; E.setMic(false); renderBar(); } });
  return onEvent;
}

function onEvent(type, d) {
  switch (type) {
    case "ring": return showRing(d);
    case "ring-stop": hideRing(d.call); if (d.why === "missed") host.notify("warn", "Missed call from " + d.from + "."); return;
    case "call": return openScreen(d.call);
    case "peer": return host.notify("sys", d.peer.user + " joined the call.");
    case "peer-gone": removePeer(d.peer); return host.notify("sys", d.peer.user + " " + d.why + ".");
    case "media": return showMedia(d.peer, d.slot);
    case "state": return peerState(d.peer, d.reaction);
    case "words": return renderTop(d.words);
    case "stats": return applyStats(d);
    case "notice": return host.notify(d.kind, d.text);
    case "ended": return closeScreen(d);
  }
}

// ---------------------------------------------------------------------------------------------- ringing
function showRing(d) {
  hideRing();
  ringBox = el("div", { cls: "call-ring", role: "alertdialog", "aria-label": "Incoming call", "data-call": d.call }, [
    el("div", { cls: "call-ring-who", text: d.from }),
    el("div", { cls: "call-ring-what", text: (d.media === "video" ? "video call" : "voice call") + " · " + host.roomLabel(d.room) +
                (d.people.length > 2 ? " · " + d.people.length + " people" : "") }),
    el("div", { cls: "call-ring-pq", text: "ML-KEM-1024 + X25519 · end-to-end encrypted" }),
    el("div", { cls: "gate-row" }, [
      el("button", { type: "button", cls: "term-btn danger", text: "decline", onclick: () => { E.decline(d.call); hideRing(); } }),
      el("button", { type: "button", cls: "term-btn primary", text: "answer", onclick: () => { hideRing(); E.accept(d.call).catch((e) => host.notify("err", e.message)); } }),
    ]),
  ]);
  document.body.append(ringBox);
  startTone();
  if (document.hidden && "Notification" in window && Notification.permission === "granted") {
    try { new Notification("CipherChat: " + d.from + " is calling", { body: "Open CipherChat to answer.", tag: "cipherchat-call", silent: true }); } catch (e) { /* not allowed here */ }
  }
}

function hideRing(id) {
  if (!ringBox || (id && ringBox.dataset.call !== id)) return;
  ringBox.remove(); ringBox = null;
  stopTone();
}

// Two soft rising tones every 2 seconds, made on the spot (no audio files)
function startTone() {
  stopTone();
  try {
    const ctx = new AudioContext();
    const beep = () => {
      [0, 0.22].forEach((t, i) => {
        const o = ctx.createOscillator(), g = ctx.createGain();
        o.type = "sine"; o.frequency.value = i ? 880 : 660;
        g.gain.setValueAtTime(0, ctx.currentTime + t);
        g.gain.linearRampToValueAtTime(0.12, ctx.currentTime + t + 0.03);
        g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + t + 0.2);
        o.connect(g).connect(ctx.destination);
        o.start(ctx.currentTime + t); o.stop(ctx.currentTime + t + 0.22);
      });
    };
    beep();
    tone = { ctx, timer: setInterval(beep, 2000) };
  } catch (e) { tone = null; }
}
function stopTone() { if (tone) { clearInterval(tone.timer); tone.ctx.close().catch(() => {}); tone = null; } }

// ---------------------------------------------------------------------------------------------- the screen
function openScreen(c) {
  clear(grid); tiles.clear();
  screen.hidden = false;
  document.body.classList.add("in-call");
  const self = tile("me", "you", true);
  self.video.srcObject = c.local.stream;
  self.video.muted = true;
  self.box.classList.add("self");
  if (c.media !== "video" || !c.local.cam) self.box.classList.add("no-video");
  renderTop(c.words || []);
  renderBar();
  timer = setInterval(() => renderClock(c), 1000);
  if (c.state === "calling") host.notify("sys", "Calling " + c.people.join(", ") + "…");
}

function closeScreen(d) {
  clearInterval(timer);
  for (const t of tiles.values()) t.video.srcObject = null;
  tiles.clear(); clear(grid);
  screen.hidden = true;
  document.body.classList.remove("in-call");
  const m = Math.floor(d.seconds / 60), s = d.seconds % 60;
  host.notify("sys", "Call ended (" + d.why + ")" + (d.call.state === "active" ? ", " + m + ":" + String(s).padStart(2, "0") : "") + ".");
}

const BLANK = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

function tile(key, name, self) {
  // a transparent poster: Android's WebView otherwise draws a grey "play" picture until the first frame arrives
  const video = el("video", { autoplay: true, playsinline: true, poster: BLANK });
  const badge = el("span", { cls: "call-badge", text: self ? "" : "connecting…" });
  const box = el("div", { cls: "call-tile", "data-key": key }, [video, el("div", { cls: "call-name" }, [el("span", { text: name }), badge])]);
  grid.append(box);
  const t = { box, video, badge, started: false };
  tiles.set(key, t);
  layout();
  return t;
}

function layout() {
  const n = tiles.size;
  grid.dataset.n = String(Math.min(n, 9));
}

function showMedia(p, slot) {
  const key = p.key + ":" + (slot === "scr" ? "scr" : "cam");
  let t = tiles.get(key);
  if (!t) t = tile(key, p.user + (slot === "scr" ? " · screen" : ""), false);
  const stream = slot === "scr" ? p.streams.scr : p.streams.cam;
  if (t.video.srcObject !== stream) t.video.srcObject = stream;
  t.video.play().catch(() => {});
  if (!t.started) {
    t.started = true;
    t.video.addEventListener("loadeddata", () => { t.badge.textContent = ""; glitchIn(t.video, "ML-KEM-1024 + X25519"); }, { once: true });
  }
  if (slot !== "scr") t.box.classList.toggle("no-video", !p.remote.cam);
}

function removePeer(p) {
  for (const k of [p.key + ":cam", p.key + ":scr"]) {
    const t = tiles.get(k);
    if (t) { t.video.srcObject = null; t.box.remove(); tiles.delete(k); }
  }
  layout();
}

function peerState(p, reaction) {
  if (!p) return;
  const t = tiles.get(p.key + ":cam");
  if (!t) return;
  t.box.classList.toggle("no-video", !p.remote.cam);
  t.box.classList.toggle("muted", !p.remote.mic);
  t.box.classList.toggle("hand", p.remote.hand);
  if (p.status && p.status !== "connected") t.badge.textContent = p.status === "connecting" || p.status === "new" ? "connecting…" : p.status;
  else if (t.started) t.badge.textContent = "";
  const scr = tiles.get(p.key + ":scr");
  if (scr && !p.remote.scr) { scr.box.remove(); tiles.delete(p.key + ":scr"); layout(); }
  if (reaction) {
    const f = el("span", { cls: "call-float", text: reaction });
    t.box.append(f);
    setTimeout(() => f.remove(), 2200);
  }
}

function applyStats(d) {
  for (const s of d.peers) {
    const t = tiles.get(s.key + ":cam");
    if (!t) continue;
    t.box.classList.toggle("speaking", s.level > 0.04);
    t.box.title = (s.w ? s.w + "×" + s.h + " " + s.fps + " fps · " : "") + (s.rtt != null ? Math.round(s.rtt * 1000) + " ms · " : "") +
                  (s.relay ? "via relay" : "direct") + " · AES-256-GCM per frame";
  }
  const f = d.frames;
  const q = top.querySelector(".call-health");
  if (q && f) {
    q.textContent = f.failed > 50 && f.failed > f.received / 20 ? "⚠ frames failing to decrypt" : "frames " + f.sent + "↑ " + f.received + "↓";
    q.classList.toggle("bad", f.failed > 50 && f.failed > f.received / 20);
  }
}

function renderClock(c) {
  const s = Math.round((Date.now() - c.started) / 1000);
  const clk = top.querySelector(".call-clock");
  if (clk) clk.textContent = (c.state === "calling" ? "ringing " : "") + Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
}

function renderTop(words) {
  const c = E.call;
  if (!c) return;
  clear(top).append(
    el("span", { cls: "call-room", text: host.roomLabel(c.room) }),
    el("span", { cls: "call-clock" }),
    el("span", { cls: "call-words", title: "Read these words aloud: everyone in the call sees the same four only if nobody is in the middle." },
       words.length ? ["call words ", ...words.map((w) => el("b", { text: w }))] : "call words appear when someone joins"),
    el("span", { cls: "grow" }),
    el("span", { cls: "call-health" }),
    el("span", { cls: "pq-badge", text: "PQ E2EE ✓", title: "Every frame AES-256-GCM, keys ML-KEM-1024 + X25519, signals ML-DSA-87 + Ed25519" }));
  renderClock(c);
}

function btn(text, title, on, fn, extra) {
  return el("button", { type: "button", cls: "term-btn call-btn" + (on ? " on" : "") + (extra ? " " + extra : ""), title, "aria-label": title,
                        "aria-pressed": on === null ? null : String(!!on), text, onclick: fn });
}

// phones (and the Android app's WebView) can't share a screen
const canShare = () => !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia);

function renderBar() {
  const c = E.call;
  if (!c) return;
  const L = c.local;
  const safe = (fn) => () => Promise.resolve(fn()).then(renderBar).catch((e) => host.notify("err", e.message));
  clear(bar).append(...[
    btn(L.micOn ? "mic" : "mic off", L.micOn ? "Mute (M)" : "Unmute (M)", L.micOn, safe(() => E.setMic(!L.micOn))),
    L.cam ? btn(L.camOn ? "cam" : "cam off", L.camOn ? "Turn the camera off (V)" : "Turn the camera on (V)", L.camOn, safe(() => E.setCam(!L.camOn))) : null,
    canShare() ? btn(L.scrOn ? "sharing" : "share", L.scrOn ? "Stop sharing your screen (S)" : "Share your screen (S)", L.scrOn, safe(() => E.shareScreen(!L.scrOn))) : null,
    E.blurAvailable ? btn("blur", "Blur your background (on this device)", blurOn, safe(async () => { blurOn = !blurOn; await E.setBlur(blurOn); })) : null,
    btn("✋", c.hand ? "Lower your hand (H)" : "Raise your hand (H)", c.hand, safe(() => E.raiseHand(!c.hand))),
    el("span", { cls: "call-react" }, QUICK.map((e) => btn(e, "React " + e, null, () => { E.react(e); peerSelf(e); }))),
    btn("ptt", ptt ? "Push-to-talk on: hold Space to talk" : "Push-to-talk off", ptt, safe(() => { ptt = !ptt; E.setMic(!ptt); })),
    btn("devices", "Choose microphone and camera", null, () => devicesMenu().catch((e) => host.notify("err", e.message))),
    el("span", { cls: "grow" }),
    btn("hang up", "Leave the call", null, () => E.hangup(), "danger")].filter(Boolean));     // absent options leave no gap
}

function peerSelf(emoji) {
  const t = tiles.get("me");
  if (!t) return;
  const f = el("span", { cls: "call-float", text: emoji });
  t.box.append(f);
  setTimeout(() => f.remove(), 2200);
}

async function devicesMenu() {
  const list = await navigator.mediaDevices.enumerateDevices();
  const pick = (kind, label, slot) => {
    const sel = el("select", { cls: "term-field", "aria-label": label });
    for (const d of list.filter((x) => x.kind === kind)) sel.append(el("option", { value: d.deviceId, text: d.label || kind }));
    sel.addEventListener("change", () => E.useDevice(slot, sel.value).catch((e) => host.notify("err", e.message)));
    return el("label", { cls: "call-dev" }, [el("span", { text: label }), sel]);
  };
  const box = el("div", { cls: "call-menu" }, [pick("audioinput", "Microphone", "mic"), pick("videoinput", "Camera", "cam"),
    el("button", { type: "button", cls: "term-btn", text: "close", onclick: () => box.remove() })]);
  bar.append(box);
}

function keys(ev) {
  if (!E || !E.call || screen.hidden || ev.target.closest("input, textarea, select")) return;
  const L = E.call.local;
  if (ev.code === "Space" && ptt && !pttDown) { ev.preventDefault(); pttDown = true; E.setMic(true); return renderBar(); }
  const k = ev.key.toLowerCase();
  if (k === "m") E.setMic(!L.micOn);
  else if (k === "v") E.setCam(!L.camOn);
  else if (k === "s" && canShare()) E.shareScreen(!L.scrOn).catch((e) => host.notify("err", e.message));
  else if (k === "h") E.raiseHand(!E.call.hand);
  else return;
  renderBar();
}
