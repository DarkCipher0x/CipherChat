// CipherChat by DarkCipher Systems: end-to-end encryption of call media, one frame at a time (docs/CALLS.md).
// Runs as a Worker beside WebRTC's encoder and decoder (RTCRtpScriptTransform, or Chromium's encoded streams).
//
//   key      AES-256-GCM, derived with HKDF-SHA-512 from the sender's key for this epoch, per LINK: sender device,
//            receiver device, epoch and stream (mic / cam / scr). Every link has its own key, so a counter nonce is
//            never reused even though each peer connection encodes the same camera separately, and a frame sent to
//            one person can't be replayed to another.
//   frame    clear codec header (VP8: 10 bytes on key frames, 3 on others; Opus: 1) || ciphertext+tag || counter (8)
//            || epoch (1) || stream (1) || clear length (1) || 0xCC. The clear bytes and the trailer are authenticated
//            (AAD); the receiver takes the clear length from the trailer, never from its own idea of the frame type.
//   rules    nothing is ever sent unencrypted: with no key yet, frames are dropped. Frames that don't decrypt, are
//            stale (more than 512 behind) or come from an unknown epoch are dropped too, and counted.
"use strict";
const MAGIC = 0xcc;
const TRAILER = 12;
const STREAMS = { mic: 1, cam: 2, scr: 3 };
const NAMES = { 1: "mic", 2: "cam", 3: "scr" };
const te = new TextEncoder();

let callId = "";
let me = "";                                 // "user|dev" of this device
const sendKeys = new Map();                  // epoch -> raw 32 bytes (this device's own sender key)
let sendEpoch = -1;
const recvKeys = new Map();                  // "user|dev" -> Map(epoch -> raw)
const derived = new Map();                   // cache: "from>to|epoch|stream" -> Promise<CryptoKey>
const stats = { sent: 0, received: 0, dropped: 0, duplicate: 0, failed: 0, why: { trailer: 0, auth: 0, length: 0, stale: 0, error: 0 } };
const bad = (why) => { stats.failed++; stats.why[why]++; };

function derive(raw, from, to, epoch, stream) {
  const id = from + ">" + to + "|" + epoch + "|" + stream;
  let k = derived.get(id);
  if (!k) {
    k = crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]).then((base) =>
      crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-512", salt: te.encode("dcx-chat/v1/call-frame|" + callId),
                                info: te.encode([from, to, epoch, NAMES[stream]].join("|")) },
                              base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]));
    derived.set(id, k);
    if (derived.size > 512) derived.delete(derived.keys().next().value);
  }
  return k;
}

function clearBytes(frame, stream) {
  if (stream === 1) return 1;                                            // Opus TOC byte
  return frame.type === "key" ? 10 : 3;                                  // VP8 payload header
}

function nonce(stream, counter) {
  const n = new Uint8Array(12);
  n[0] = stream;
  new DataView(n.buffer).setBigUint64(4, counter);
  return n;
}

function encryptor(opts) {
  const stream = STREAMS[opts.stream];
  let counter = 0n, epoch = -1;
  return async (frame, ctl) => {
    if (sendEpoch < 0) { stats.dropped++; return; }                      // no key yet: never send in the clear
    if (epoch !== sendEpoch) { epoch = sendEpoch; counter = 0n; }
    const data = new Uint8Array(frame.data);
    if (data.length === 0) { ctl.enqueue(frame); return; }
    const n = Math.min(clearBytes(frame, stream), data.length);
    const key = await derive(sendKeys.get(epoch), me, opts.peer, epoch, stream);
    counter += 1n;
    const meta = new Uint8Array(TRAILER);
    new DataView(meta.buffer).setBigUint64(0, counter);
    meta[8] = epoch & 0xff; meta[9] = stream; meta[10] = n; meta[11] = MAGIC;
    const head = data.subarray(0, n);
    const aad = new Uint8Array(n + TRAILER); aad.set(head); aad.set(meta, n);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce(stream, counter), additionalData: aad }, key, data.subarray(n)));
    const out = new Uint8Array(n + ct.length + TRAILER);
    out.set(head); out.set(ct, n); out.set(meta, n + ct.length);
    frame.data = out.buffer;
    stats.sent++;
    ctl.enqueue(frame);
  };
}

function decryptor(opts) {
  const seen = new Map();                                                // "epoch|stream" -> {max, recent: Set}
  return async (frame, ctl) => {
    const data = new Uint8Array(frame.data);
    if (data.length === 0) { ctl.enqueue(frame); return; }
    if (data.length < TRAILER + 16 + 1 || data[data.length - 1] !== MAGIC) { bad("trailer"); return; }
    const meta = data.subarray(data.length - TRAILER);
    const counter = new DataView(meta.buffer, meta.byteOffset).getBigUint64(0);
    const eByte = meta[8], stream = meta[9];
    if (!NAMES[stream]) { bad("trailer"); return; }
    const keys = recvKeys.get(opts.peer);
    const epoch = keys && [...keys.keys()].filter((e) => (e & 0xff) === eByte).pop();
    if (epoch === undefined) { stats.dropped++; return; }                // key not here yet (it's on its way)
    const n = meta[10];
    if (n > data.length - TRAILER - 16) { bad("length"); return; }
    const head = data.subarray(0, n);
    const aad = new Uint8Array(n + TRAILER); aad.set(head); aad.set(meta, n);
    let plain;
    try {
      const key = await derive(keys.get(epoch), opts.peer, me, epoch, stream);
      plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce(stream, counter), additionalData: aad }, key,
                                                         data.subarray(n, data.length - TRAILER)));
    } catch (e) { bad("auth"); return; }
    // Freshness, checked only on authentic frames (a forged frame can never move the window): anything more than 512
    // frames behind is refused. The browser itself re-delivers a frame now and then (the first key frame while the
    // decoder starts); those are authentic and recent, so they pass. Network replays are already stopped by SRTP.
    const w = seen.get(epoch + "|" + stream) || { max: 0n, recent: new Set() };
    if (counter <= w.max - 512n) { bad("stale"); return; }
    if (w.recent.has(counter)) stats.duplicate++;
    w.recent.add(counter);
    if (w.recent.size > 1024) w.recent.delete(w.recent.values().next().value);
    if (counter > w.max) w.max = counter;
    seen.set(epoch + "|" + stream, w);
    const out = new Uint8Array(n + plain.length);
    out.set(head); out.set(plain, n);
    frame.data = out.buffer;
    stats.received++;
    ctl.enqueue(frame);
  };
}

function attach(readable, writable, opts) {
  const fn = opts.dir === "send" ? encryptor(opts) : decryptor(opts);
  readable.pipeThrough(new TransformStream({ transform: (frame, ctl) => fn(frame, ctl).catch(() => bad("error")) }))
          .pipeTo(writable).catch(() => {});
}

// RTCRtpScriptTransform (Firefox, Safari, newer Chromium)
self.onrtctransform = (ev) => attach(ev.transformer.readable, ev.transformer.writable, ev.transformer.options);

self.onmessage = (ev) => {
  const m = ev.data;
  if (m.type === "init") { callId = m.call; me = m.self; }
  else if (m.type === "stream") attach(m.readable, m.writable, m.options);          // Chromium encoded streams
  else if (m.type === "sendKey") {
    sendKeys.set(m.epoch, new Uint8Array(m.key));
    sendEpoch = m.epoch;
    for (const e of [...sendKeys.keys()]) if (e < m.epoch - 2) sendKeys.delete(e);
  } else if (m.type === "recvKey") {
    const keys = recvKeys.get(m.peer) || new Map();
    keys.set(m.epoch, new Uint8Array(m.key));
    for (const e of [...keys.keys()]) if (e < m.epoch - 2) keys.delete(e);              // the last few, for frames in flight
    recvKeys.set(m.peer, keys);
  } else if (m.type === "forget") {
    recvKeys.delete(m.peer);
  } else if (m.type === "wipe") {
    sendKeys.clear(); recvKeys.clear(); derived.clear(); sendEpoch = -1;
  }
};

setInterval(() => postMessage({ type: "stats", stats }), 2000);
