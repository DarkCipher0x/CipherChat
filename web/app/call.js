// CipherChat by DarkCipher Systems: the call engine (docs/CALLS.md). Voice and video calls between the members of a
// room: a mesh of WebRTC connections (up to 8 people), every frame end-to-end encrypted by callworker.js under
// per-sender keys that travel ML-KEM-1024 + X25519-wrapped inside signed signals (callcrypto.js).
//
// No UI here: the host (the web portal's app.js, or the Windows / Android app's bridge) gives it
//   host = { user, dev, api(path, body), trusted(user) -> truthy if verified, onEvent(type, detail),
//            seal(fields) -> {h, s}, open(item) -> header, wrapKey(key32, call, epoch, users) -> {epoch, keys},
//            unwrapKey(header) -> key32, words(call, users) -> [4 words] }
// The seal/open/wrap/unwrap/words functions are callcrypto.js in the browser; in the native apps they run in native
// code, so identity private keys never enter the WebView. Only the random per-call media keys live here.
// and passes every poll()'s `signals` to handleSignals(). Events: "ring", "ring-stop", "call", "peer", "peer-gone",
// "media", "state", "stats", "words", "ended", "notice".
import * as C from "./crypto.js";
import { newCallId } from "./callcrypto.js";

const RING_MS = 45000;
const ROTATE_MS = 10 * 60 * 1000;                 // a fresh sender key at least this often
const SWITCH_DELAY_MS = 400;                      // new key goes out first, then frames use it
const MAX_PEOPLE = 8;
const SLOTS = ["mic", "cam", "scr"];              // transceiver order in every connection

export function supported() {
  const pc = window.RTCPeerConnection;
  if (!pc || !navigator.mediaDevices || !window.Worker) return { ok: false, why: "this browser has no WebRTC" };
  if (window.RTCRtpScriptTransform) return { ok: true, api: "script" };
  if (window.RTCRtpSender && "createEncodedStreams" in RTCRtpSender.prototype) return { ok: true, api: "streams" };
  return { ok: false, why: "this browser can't encrypt call media end to end (no encoded transforms), so CipherChat won't call from it" };
}

function bitrateFor(n) {                          // n = how many people this device sends to
  if (n <= 1) return { max: 4_500_000, scale: 1 };
  if (n === 2) return { max: 2_500_000, scale: 1 };
  if (n <= 4) return { max: 1_400_000, scale: 1.5 };
  return { max: 800_000, scale: 2 };
}

export class CallEngine {
  constructor(host) {
    this.h = host;
    this.call = null;                             // the one active (or ringing-out) call
    this.ringing = new Map();                     // call id -> incoming ring {sig, timer}
    this.seen = new Set();
    this.cap = supported();
  }

  // ------------------------------------------------------------------------------------------ signalling
  async send(kind, to, fields) {
    const c = this.call;
    const sig = await this.h.seal(Object.assign({ kind, room: fields.room || c.room, call: fields.call || c.id, dev: this.h.dev, to }, fields));
    await this.h.api("calls/signal", { room: fields.room || c.room, to, sig });
  }

  async handleSignals(items) {
    for (const it of items || []) {
      let s;
      try { s = await this.h.open(it, this.seen); }
      catch (e) { continue; }                     // unverifiable signals are ignored, never acted on
      if (s.dev === this.h.dev) continue;         // our own, echoed back
      try { await this.on(s); } catch (e) { this.h.onEvent("notice", { kind: "err", text: "Call problem: " + e.message }); }
    }
  }

  async on(s) {
    const c = this.call;
    const mine = s.from === this.h.user;          // another device of this account
    if (s.kind === "ring") {
      if (mine) return;
      if (c && c.id !== s.call) return this.sendTo("busy", [s.from], { room: s.room, call: s.call });
      if (c || this.ringing.has(s.call)) return;
      const timer = setTimeout(() => this.stopRing(s.call, "missed"), RING_MS);
      this.ringing.set(s.call, { sig: s, timer });
      return this.h.onEvent("ring", { call: s.call, room: s.room, from: s.from, media: s.media === "video" ? "video" : "audio",
                                      people: (s.people || []).filter((u) => typeof u === "string").slice(0, MAX_PEOPLE) });
    }
    if (s.kind === "accept" && mine) return this.stopRing(s.call, "answered on another device");
    if (s.kind === "decline" && mine) return this.stopRing(s.call, "declined on another device");
    if (s.kind === "end" && this.ringing.has(s.call)) return this.stopRing(s.call, "missed");
    if (!c || c.id !== s.call || mine) return;
    const peerKey = s.from + "|" + s.dev;
    switch (s.kind) {
      case "accept": return this.addPeer(s.from, s.dev);
      case "decline": case "busy":
        if (c.state === "calling" && c.people.length === 1) return this.end(s.kind === "busy" ? "busy" : "declined");
        return this.h.onEvent("notice", { kind: "sys", text: s.from + (s.kind === "busy" ? " is on another call." : " declined.") });
      case "key": {
        if (!c.peers.has(peerKey) && c.state === "active") await this.addPeer(s.from, s.dev);
        const key = await this.h.unwrapKey(s);
        this.worker.postMessage({ type: "recvKey", peer: peerKey, epoch: s.epoch, key: key.buffer }, [key.buffer]);
        return;
      }
      case "offer": if (s.target_dev === this.h.dev) return this.onOffer(s); return;
      case "answer": if (s.target_dev === this.h.dev) return this.onAnswer(s); return;
      case "ice": if (s.target_dev === this.h.dev) return this.onIce(s); return;
      case "state": {
        const p = c.peers.get(peerKey);
        if (p) { p.remote = { mic: !!s.mic, cam: !!s.cam, scr: !!s.scr, hand: !!s.hand }; this.h.onEvent("state", { peer: p }); }
        if (typeof s.reaction === "string" && [...s.reaction].length <= 2) this.h.onEvent("state", { peer: p, reaction: s.reaction });
        return;
      }
      case "leave": case "end": return this.dropPeer(peerKey, s.kind === "end" ? "ended the call" : "left");
    }
  }

  sendTo(kind, to, fields) {
    return this.h.seal(Object.assign({ kind, dev: this.h.dev, to }, fields))
      .then((sig) => this.h.api("calls/signal", { room: fields.room, to, sig })).catch(() => {});
  }

  stopRing(id, why) {
    const r = this.ringing.get(id);
    if (!r) return;
    clearTimeout(r.timer);
    this.ringing.delete(id);
    this.h.onEvent("ring-stop", { call: id, why, from: r.sig.from, room: r.sig.room });
  }

  // ------------------------------------------------------------------------------------------ starting and answering
  async start(room, media, people) {
    if (!this.cap.ok) throw new Error("Calls aren't possible here: " + this.cap.why + ".");
    if (this.call) throw new Error("You're already in a call.");
    people = [...new Set(people)].filter((u) => u !== this.h.user);
    if (!people.length) throw new Error("There's nobody else in this room to call.");
    if (people.length > MAX_PEOPLE - 1) throw new Error("Calls are up to " + MAX_PEOPLE + " people.");
    const untrusted = people.filter((u) => !this.h.trusted(u));
    if (untrusted.length) throw new Error("Verify " + untrusted.join(", ") + " first: calls only go to verified identities.");
    await this.begin(newCallId(), room, media, people, this.h.user, "calling");
    await this.send("ring", people, { media, people: [this.h.user, ...people] });
    this.call.ringTimer = setTimeout(() => {
      const c = this.call;
      if (!c || c.state !== "calling") return;
      this.send("end", c.people, {}).catch(() => {}).finally(() => this.end("no answer"));   // everyone stops ringing at once
    }, RING_MS);
  }

  async accept(id) {
    const r = this.ringing.get(id);
    if (!r) throw new Error("That call isn't ringing any more.");
    if (this.call) throw new Error("You're already in a call.");
    this.stopRing(id, "answered");
    const s = r.sig;
    const people = (s.people || [s.from]).filter((u) => typeof u === "string" && u !== this.h.user && this.h.trusted(u));
    await this.begin(s.call, s.room, s.media === "video" ? "video" : "audio", people, s.from, "active");
    await this.send("accept", people, {});
    await this.addPeer(s.from, s.dev);
  }

  decline(id) {
    const r = this.ringing.get(id);
    if (!r) return;
    this.stopRing(id, "declined");
    this.sendTo("decline", [r.sig.from], { room: r.sig.room, call: id });
  }

  async begin(id, room, media, people, caller, state) {
    const ice = await this.h.api("calls/turn").catch(() => ({ ice_servers: [], relay_only: false }));
    const local = await this.capture(media);
    this.worker = new Worker(new URL("./callworker.js", import.meta.url));
    this.worker.postMessage({ type: "init", call: id, self: this.h.user + "|" + this.h.dev });
    this.worker.onmessage = (ev) => { if (ev.data.type === "stats") this.frameStats = ev.data.stats; };
    this.call = { id, room, media, people, caller, state, peers: new Map(), epoch: -1, local, ice, hand: false,
                  started: Date.now(), statsTimer: setInterval(() => this.stats(), 2000), rotateTimer: setInterval(() => this.rotate(), ROTATE_MS) };
    this.h.onEvent("call", { call: this.call });
    await this.rotate();
  }

  async capture(media) {
    const audio = { echoCancellation: true, noiseSuppression: true, autoGainControl: true, channelCount: 1 };
    const video = media === "video" ? { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30, max: 30 } } : false;
    let stream;
    try { stream = await navigator.mediaDevices.getUserMedia({ audio, video }); }
    catch (e) {
      if (!video) throw new Error("No microphone available (" + e.name + ").");
      stream = await navigator.mediaDevices.getUserMedia({ audio, video: false });
      this.h.onEvent("notice", { kind: "warn", text: "No camera available (" + e.name + "), so this is a voice call from your side." });
    }
    const cam = stream.getVideoTracks()[0] || null;
    if (cam) {
      cam.contentHint = "motion";
      const caps = cam.getCapabilities ? cam.getCapabilities() : {};
      if (caps.backgroundBlur && caps.backgroundBlur.includes && caps.backgroundBlur.includes(true)) this.blurAvailable = true;
    }
    const local = { stream, mic: stream.getAudioTracks()[0] || null, cam, scr: null, micOn: true, camOn: !!cam, scrOn: false, video };
    this.watch(local, "mic"); this.watch(local, "cam");
    return local;
  }

  // A camera or microphone can stop on its own (unplugged, taken by another app, the system's privacy switch): try
  // once to get it back and swap it into every connection, or say what happened.
  watch(local, slot) {
    const track = local[slot];
    if (!track) return;
    track.onended = async () => {
      if (!this.call || this.call.local !== local || local[slot] !== track) return;      // we stopped it ourselves
      const now = Date.now();
      local.retries = (local.retries || []).filter((r) => now - r.at < 30000);
      if (local.retries.filter((r) => r.slot === slot).length >= 3) {
        if (slot === "cam") { local.camOn = false; this.broadcastState(); }
        return this.h.onEvent("notice", { kind: "err", text: (slot === "mic" ? "The microphone" : "The camera") + " keeps stopping, so CipherChat stopped retrying. Pick another one under devices." });
      }
      local.retries.push({ at: now, slot });
      this.h.onEvent("notice", { kind: "warn", text: (slot === "mic" ? "Your microphone" : "Your camera") + " stopped; trying to get it back…" });
      await new Promise((r) => setTimeout(r, 800));
      try {
        const s = await navigator.mediaDevices.getUserMedia(slot === "mic"
          ? { audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true, channelCount: 1 } } : { video: local.video || true });
        const fresh = slot === "mic" ? s.getAudioTracks()[0] : s.getVideoTracks()[0];
        if (!this.call || this.call.local !== local) { fresh.stop(); return; }
        fresh.enabled = slot === "mic" ? local.micOn : local.camOn;
        if (slot === "cam") fresh.contentHint = "motion";
        local.stream.removeTrack(track); local.stream.addTrack(fresh);
        local[slot] = fresh;
        this.replace(slot, fresh);
        this.watch(local, slot);
        this.h.onEvent("notice", { kind: "sys", text: (slot === "mic" ? "Microphone" : "Camera") + " back." });
      } catch (e) {
        if (slot === "cam") { local.camOn = false; this.broadcastState(); }
        this.h.onEvent("notice", { kind: "err", text: "Couldn't get the " + (slot === "mic" ? "microphone" : "camera") + " back (" + e.name + ")." });
      }
    };
  }

  // ------------------------------------------------------------------------------------------ keys
  participants() {
    return [...new Set([...this.call.peers.values()].map((p) => p.user))].filter((u) => this.h.trusted(u));
  }

  async rotate() {
    const c = this.call;
    if (!c) return;
    c.epoch += 1;
    const epoch = c.epoch, key = C.random(32);
    const who = this.participants();
    if (who.length) await this.send("key", who, await this.h.wrapKey(key, c.id, epoch, who));
    if (who.length) {                             // a key nobody else holds would only produce frames nobody can open
      const copy = key.slice();
      setTimeout(() => { if (this.call === c && this.worker) this.worker.postMessage({ type: "sendKey", epoch, key: copy.buffer }, [copy.buffer]); },
                 SWITCH_DELAY_MS);
    }
    key.fill(0);
    c.words = who.length ? await this.h.words(c.id, [this.h.user, ...who]) : [];
    this.h.onEvent("words", { words: c.words, people: who.length + 1 });
  }

  // ------------------------------------------------------------------------------------------ peers
  async addPeer(user, dev) {
    const c = this.call;
    const key = user + "|" + dev;
    if (!c || c.peers.has(key) || !this.h.trusted(user)) return;
    if (c.peers.size >= MAX_PEOPLE - 1) return this.h.onEvent("notice", { kind: "warn", text: user + " couldn't join: the call is full." });
    clearTimeout(c.ringTimer);
    c.state = "active";
    const p = { key, user, dev, pc: null, remote: { mic: true, cam: c.media === "video", scr: false, hand: false }, iceQueue: [],
                streams: { cam: new MediaStream(), scr: new MediaStream() }, status: "connecting" };
    c.peers.set(key, p);
    this.h.onEvent("peer", { peer: p });
    await this.rotate();                          // the newcomer gets a fresh key; they can't hear what came before
    if ((this.h.user + "|" + this.h.dev) < key) await this.makeOffer(p);
  }

  dropPeer(key, why) {
    const c = this.call;
    const p = c && c.peers.get(key);
    if (!p) return;
    try { p.pc && p.pc.close(); } catch (e) { /* already closed */ }
    c.peers.delete(key);
    this.worker.postMessage({ type: "forget", peer: key });
    this.h.onEvent("peer-gone", { peer: p, why });
    if (!c.peers.size && c.state === "active") return this.end("everyone left");
    this.rotate();                                // whoever left can't hear what comes next
    this.tune();
  }

  connection(p) {
    const c = this.call;
    const pc = new RTCPeerConnection({ iceServers: c.ice.ice_servers || [], iceTransportPolicy: c.ice.relay_only ? "relay" : "all",
                                       bundlePolicy: "max-bundle", rtcpMuxPolicy: "require",
                                       encodedInsertableStreams: this.cap.api === "streams" });
    pc.onicecandidate = (ev) => {
      if (ev.candidate) this.send("ice", [p.user], { target_dev: p.dev, cand: ev.candidate.candidate, mid: ev.candidate.sdpMid,
                                                     mline: ev.candidate.sdpMLineIndex }).catch(() => {});
    };
    pc.onconnectionstatechange = () => {
      p.status = pc.connectionState;
      this.h.onEvent("state", { peer: p });
      if (pc.connectionState === "failed" && (this.h.user + "|" + this.h.dev) < p.key) { pc.restartIce(); this.makeOffer(p, true); }
    };
    pc.ontrack = (ev) => {
      const slot = SLOTS[pc.getTransceivers().indexOf(ev.transceiver)] || "cam";
      this.protectReceiver(ev.receiver, p);
      if (slot === "mic") { p.streams.cam.addTrack(ev.track); }
      else p.streams[slot].addTrack(ev.track);
      this.h.onEvent("media", { peer: p, slot });
    };
    p.pc = pc;
    return pc;
  }

  protectSender(sender, p, slot) {
    if (sender.cipherchat) return;
    sender.cipherchat = true;
    const options = { dir: "send", stream: slot, peer: p.key };
    if (this.cap.api === "script") sender.transform = new RTCRtpScriptTransform(this.worker, options);
    else { const s = sender.createEncodedStreams(); this.worker.postMessage({ type: "stream", readable: s.readable, writable: s.writable, options }, [s.readable, s.writable]); }
  }

  protectReceiver(receiver, p) {
    if (receiver.cipherchat) return;
    receiver.cipherchat = true;
    const options = { dir: "recv", peer: p.key };
    if (this.cap.api === "script") receiver.transform = new RTCRtpScriptTransform(this.worker, options);
    else { const s = receiver.createEncodedStreams(); this.worker.postMessage({ type: "stream", readable: s.readable, writable: s.writable, options }, [s.readable, s.writable]); }
  }

  prepare(t, slot, p) {
    const kind = slot === "mic" ? "audio" : "video";
    const caps = RTCRtpReceiver.getCapabilities && RTCRtpReceiver.getCapabilities(kind);
    if (caps && t.setCodecPreferences) {
      const want = kind === "audio" ? /^audio\/opus$/i : /^video\/VP8$/i;     // VP8: its packetizer works on encrypted payloads
      const pref = caps.codecs.filter((x) => want.test(x.mimeType)).concat(caps.codecs.filter((x) => /rtx|red|ulpfec/i.test(x.mimeType) && kind === "video"));
      try { if (pref.length) t.setCodecPreferences(pref); } catch (e) { /* keep the browser's order */ }
    }
    t.direction = "sendrecv";
    this.protectSender(t.sender, p, slot);
    this.protectReceiver(t.receiver, p);
    const L = this.call.local;
    t.sender.replaceTrack(slot === "mic" ? L.mic : slot === "cam" ? L.cam : L.scr);
  }

  async makeOffer(p, restart) {
    const pc = p.pc || this.connection(p);
    if (!restart) for (const slot of SLOTS) this.prepare(pc.addTransceiver(slot === "mic" ? "audio" : "video", { direction: "sendrecv" }), slot, p);
    const offer = await pc.createOffer(restart ? { iceRestart: true } : {});
    await pc.setLocalDescription(offer);
    await this.send("offer", [p.user], { target_dev: p.dev, sdp: pc.localDescription.sdp });
    this.tune();
  }

  async onOffer(s) {
    const c = this.call;
    const key = s.from + "|" + s.dev;
    if (!c.peers.has(key)) await this.addPeer(s.from, s.dev);
    const p = c.peers.get(key);
    if (!p) return;
    const pc = p.pc || this.connection(p);
    const fresh = !pc.remoteDescription;
    await pc.setRemoteDescription({ type: "offer", sdp: String(s.sdp) });
    if (fresh) pc.getTransceivers().slice(0, 3).forEach((t, i) => this.prepare(t, SLOTS[i], p));
    await pc.setLocalDescription(await pc.createAnswer());
    await this.send("answer", [p.user], { target_dev: p.dev, sdp: pc.localDescription.sdp });
    this.flushIce(p);
    this.tune();
  }

  async onAnswer(s) {
    const p = this.call.peers.get(s.from + "|" + s.dev);
    if (!p || !p.pc || p.pc.signalingState !== "have-local-offer") return;
    await p.pc.setRemoteDescription({ type: "answer", sdp: String(s.sdp) });
    this.flushIce(p);
  }

  async onIce(s) {
    const p = this.call.peers.get(s.from + "|" + s.dev);
    if (!p) return;
    const cand = { candidate: String(s.cand || ""), sdpMid: s.mid == null ? null : String(s.mid), sdpMLineIndex: Number.isInteger(s.mline) ? s.mline : null };
    if (!p.pc || !p.pc.remoteDescription) { p.iceQueue.push(cand); return; }
    await p.pc.addIceCandidate(cand).catch(() => {});
  }

  flushIce(p) {
    for (const cand of p.iceQueue.splice(0)) p.pc.addIceCandidate(cand).catch(() => {});
  }

  // ------------------------------------------------------------------------------------------ during the call
  tune() {
    const c = this.call;
    if (!c) return;
    const { max, scale } = bitrateFor(c.peers.size);
    for (const p of c.peers.values()) {
      if (!p.pc) continue;
      p.pc.getTransceivers().slice(0, 3).forEach((t, i) => {
        if (SLOTS[i] === "mic") return;
        const params = t.sender.getParameters();
        if (!params.encodings || !params.encodings.length) return;
        params.encodings[0].maxBitrate = SLOTS[i] === "scr" ? 3_000_000 : max;
        params.encodings[0].scaleResolutionDownBy = SLOTS[i] === "scr" ? 1 : scale;
        params.degradationPreference = SLOTS[i] === "scr" ? "maintain-resolution" : "maintain-framerate";
        t.sender.setParameters(params).catch(() => {});
      });
    }
  }

  replace(slot, track) {
    for (const p of this.call.peers.values()) {
      const t = p.pc && p.pc.getTransceivers()[SLOTS.indexOf(slot)];
      if (t) t.sender.replaceTrack(track).catch(() => {});
    }
  }

  setMic(on) {
    const L = this.call.local;
    L.micOn = !!on;
    if (L.mic) L.mic.enabled = L.micOn;
    this.broadcastState();
  }

  setCam(on) {
    const L = this.call.local;
    if (!L.cam) return false;
    L.camOn = !!on;
    L.cam.enabled = L.camOn;
    this.broadcastState();
    return true;
  }

  async shareScreen(on) {
    const L = this.call.local;
    if (on) {
      const s = await navigator.mediaDevices.getDisplayMedia({ video: { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } }, audio: false });
      L.scr = s.getVideoTracks()[0];
      L.scr.contentHint = "detail";
      L.scr.onended = () => this.shareScreen(false);
      L.scrOn = true;
      this.replace("scr", L.scr);
    } else {
      if (L.scr) L.scr.stop();
      L.scr = null; L.scrOn = false;
      this.replace("scr", null);
    }
    this.tune();
    this.broadcastState();
  }

  async useDevice(kind, deviceId) {
    const L = this.call.local;
    const constraints = kind === "mic" ? { audio: { deviceId: { exact: deviceId }, echoCancellation: true, noiseSuppression: true, autoGainControl: true } }
                                       : { video: { deviceId: { exact: deviceId }, width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } } };
    const s = await navigator.mediaDevices.getUserMedia(constraints);
    const track = kind === "mic" ? s.getAudioTracks()[0] : s.getVideoTracks()[0];
    const old = L[kind];
    L[kind] = track;
    L.stream.removeTrack(old); L.stream.addTrack(track);
    track.enabled = kind === "mic" ? L.micOn : L.camOn;
    this.replace(kind, track);
    this.watch(L, kind);
    if (old) old.stop();
  }

  async setBlur(on) {
    const cam = this.call.local.cam;
    if (!cam || !this.blurAvailable) return false;
    await cam.applyConstraints({ backgroundBlur: !!on });
    return true;
  }

  raiseHand(up) { this.call.hand = !!up; this.broadcastState(); }

  react(emoji) { this.broadcastState({ reaction: emoji }); }

  broadcastState(extra) {
    const c = this.call;
    const to = [...new Set([...c.peers.values()].map((p) => p.user))];
    if (!to.length) return;
    const L = c.local;
    this.send("state", to, Object.assign({ mic: L.micOn, cam: L.camOn, scr: L.scrOn, hand: c.hand }, extra || {})).catch(() => {});
  }

  async stats() {
    const c = this.call;
    if (!c) return;
    const out = { frames: this.frameStats || null, peers: [] };
    for (const p of c.peers.values()) {
      if (!p.pc) continue;
      const r = await p.pc.getStats().catch(() => null);
      if (!r) continue;
      const s = { key: p.key, user: p.user, w: 0, h: 0, fps: 0, rtt: null, relay: false, level: 0 };
      r.forEach((x) => {
        if (x.type === "inbound-rtp" && x.kind === "video" && x.frameWidth) { s.w = Math.max(s.w, x.frameWidth); s.h = Math.max(s.h, x.frameHeight); s.fps = Math.max(s.fps, Math.round(x.framesPerSecond || 0)); }
        if (x.type === "inbound-rtp" && x.kind === "audio" && typeof x.audioLevel === "number") s.level = x.audioLevel;
        if (x.type === "candidate-pair" && x.nominated && x.state === "succeeded") {
          s.rtt = x.currentRoundTripTime;
          const local = r.get(x.localCandidateId);
          s.relay = !!(local && local.candidateType === "relay");
        }
      });
      out.peers.push(s);
    }
    this.h.onEvent("stats", out);
  }

  // ------------------------------------------------------------------------------------------ ending
  async hangup() {
    const c = this.call;
    if (!c) return;
    const to = [...new Set([...c.people, ...[...c.peers.values()].map((p) => p.user)])];
    if (to.length) await this.send(c.state === "calling" ? "end" : "leave", to, {}).catch(() => {});
    this.end("you hung up");
  }

  end(why) {
    const c = this.call;
    if (!c) return;
    this.call = null;
    clearTimeout(c.ringTimer); clearInterval(c.statsTimer); clearInterval(c.rotateTimer);
    for (const p of c.peers.values()) { try { p.pc && p.pc.close(); } catch (e) { /* closed */ } }
    for (const t of [c.local.mic, c.local.cam, c.local.scr]) if (t) t.stop();
    if (this.worker) { this.worker.postMessage({ type: "wipe" }); this.worker.terminate(); this.worker = null; }
    this.h.onEvent("ended", { call: c, why, seconds: Math.round((Date.now() - c.started) / 1000) });
  }
}
