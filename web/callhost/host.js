// CipherChat for Windows and Android: the call screen's page. It runs the web portal's call engine (call.js) and call
// screen (callui.js) unchanged; every cryptographic step that needs the identity, and every request to the server, is
// asked of the app (Calls.cs on Windows, Calls.kt on Android) through the WebView's message channel, so private keys
// never enter this page.
import { CallEngine } from "./app/call.js";
import * as UI from "./app/callui.js";
import { b64, unb64 } from "./app/crypto.js";

// The app's message channel: WebView2's (objects) on Windows; on Android an androidx.webkit WebMessageListener that
// the app registered for this page's origin only (strings, so JSON).
const app = (() => {
  const wv = window.chrome && window.chrome.webview;
  if (wv) return { post: (m) => wv.postMessage(m), listen: (f) => wv.addEventListener("message", (ev) => f(ev.data)) };
  const a = window.cipherchatHost;
  return { post: (m) => a.postMessage(JSON.stringify(m)), listen: (f) => { a.onmessage = (ev) => f(JSON.parse(ev.data)); } };
})();
const pending = new Map();
let next = 1, trusted = new Set(), labels = {}, engine = null;

function ask(op, args) {
  return new Promise((resolve, reject) => {
    const id = next++;
    pending.set(id, { resolve, reject });
    app.post({ id, op, args });
  });
}
const tell = (event, detail) => app.post({ event, detail });

// Development builds with fake media only: a drawn camera and a tone, so end-to-end runs don't depend on capture devices
function fakeMedia(user) {
  const canvas = document.createElement("canvas");
  canvas.width = 1280; canvas.height = 720;
  const g = canvas.getContext("2d");
  let n = 0;
  setInterval(() => { n++; g.fillStyle = "#0b1f3a"; g.fillRect(0, 0, 1280, 720); g.fillStyle = "#36d2cb"; g.font = "64px monospace"; g.fillText((window.chrome && window.chrome.webview ? "windows" : "android") + " · " + user + " · " + n, 60, 380); }, 66);
  const ac = new AudioContext();
  const o = ac.createOscillator(), dst = ac.createMediaStreamDestination();
  o.frequency.value = 330; o.connect(dst); o.start();
  navigator.mediaDevices.getUserMedia = async () => new MediaStream([...canvas.captureStream(15).getVideoTracks(), ...dst.stream.getAudioTracks()]);
}

function start(init) {
  if (init.fakeMedia) fakeMedia(init.user);
  trusted = new Set(init.trusted);
  labels = init.labels || {};
  const onEvent = UI.mount(null, {
    roomLabel: (id) => labels[id] || "a room",
    notify: (kind, text) => tell("notice", { kind, text }),
  });
  const forward = (type, d) => {
    onEvent(type, d);
    if (type === "ended") tell("ended", { why: d.why, seconds: d.seconds });
    if (type === "words") tell("words", { words: d.words });
  };
  engine = new CallEngine({
    user: init.user, dev: init.dev, trusted: (u) => trusted.has(u), onEvent: forward,
    api: (path, body) => ask("api", { path, body }),
    seal: (fields) => ask("seal", fields),
    open: (item) => ask("open", item),
    wrapKey: (key32, call, epoch, users) => ask("wrapKey", { key: b64(key32), call, epoch, users }),
    unwrapKey: async (sig) => unb64(await ask("unwrapKey", sig)),
    words: (call, users) => ask("words", { call, users }),
  });
  UI.bind(engine);
  document.getElementById("wait").remove();
  if (init.diag) setInterval(() => {                 // development builds only: what the call is doing, for the app's log
    const c = engine.call;
    const L = c && c.local;
    const t = (x) => x && { state: x.readyState, enabled: x.enabled, muted: x.muted, label: x.label, size: x.getSettings ? x.getSettings().width + "x" + x.getSettings().height : "" };
    tell("diag", { call: !!c, mic: t(L && L.mic), cam: t(L && L.cam), frames: engine.frameStats || null,
                   peers: c ? [...c.peers.values()].map((p) => ({ key: p.key, status: p.status })) : [] });
  }, 4000);
}

app.listen(async (m) => {
  if (m.reply) {
    const p = pending.get(m.reply);
    if (!p) return;
    pending.delete(m.reply);
    return m.ok ? p.resolve(m.value) : p.reject(new Error(m.error || "refused"));
  }
  try {
    if (m.event === "init") start(m.detail);
    else if (m.event === "trust") trusted = new Set(m.detail.trusted);
    else if (m.event === "signals") await engine.handleSignals(m.detail.items);
    else if (m.event === "start") await engine.start(m.detail.room, m.detail.media, m.detail.people);
    else if (m.event === "answer") { await engine.handleSignals(m.detail.items); await engine.accept(m.detail.call); }
    else if (m.event === "hangup") await engine.hangup();
  } catch (e) {
    tell("notice", { kind: "err", text: e.message });
    if (m.event === "start" || m.event === "answer") tell("ended", { why: e.message, seconds: 0 });
  }
});

window.addEventListener("beforeunload", () => { if (engine && engine.call) engine.hangup(); });
tell("ready", {});
