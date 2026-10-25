// CipherChat call tests (test page only, never shipped): the frame worker on its own, then whole calls between two
// engines in this page over real WebRTC, with real hybrid identities and an in-memory signal relay.
import * as C from "../app/crypto.js";
import { CallEngine } from "../app/call.js";
import { webHost } from "../app/callcrypto.js";

const out = document.getElementById("out");
const results = (window.__results = { done: false, pass: 0, fail: 0, lines: [] });
function log(ok, name, detail) {
  results[ok ? "pass" : "fail"]++;
  const line = (ok ? "PASS " : "FAIL ") + name + (detail ? "  (" + detail + ")" : "");
  results.lines.push(line);
  out.textContent += line + "\n";
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms, step = 100) {
  for (let t = 0; t < ms; t += step) { if (await fn()) return true; await sleep(step); }
  return false;
}

// ---------------------------------------------------------------------------------------------- 0. Windows -> browser
// fixtures/windows-call.json is written by the Windows tests (CallTests.WindowsMakesACallFixtureForTheBrowser)
async function fixtureTests() {
  const K = await import("../app/callcrypto.js");
  const f = await (await fetch("fixtures/windows-call.json", { cache: "no-store" })).json();
  const alice = await C.openIdentity({ b: f.alice.b, s: f.alice.s }, "alice");
  const bob = await C.identityFromMaster("bob", C.fromHex(f.bob_master));
  const bobFp = (await C.publishIdentity(bob, 1790000000000)).fp;
  const realNow = Date.now;
  Date.now = () => f.made_at;                       // the fixture's own time, so the freshness rule still applies
  try {
    const sig = await K.openSignal(f.item, (u) => (u === "alice" ? { pub: alice, fp: alice.fp } : null), new Set());
    log(sig.kind === "key" && sig.from === "alice", "a call signal Windows signed verifies here (ML-DSA-87 + Ed25519)");
    const key = await K.unwrapSenderKey(sig, bob, bobFp);
    log(C.hex(key) === f.key, "and the sender key Windows wrapped (ML-KEM-1024 + X25519) opens to the same bytes");
    let refused = false;
    try { await K.openSignal(f.item, () => null, new Set()); } catch (e) { refused = true; }
    log(refused, "the same signal is refused when its sender isn't trusted");
  } finally { Date.now = realNow; }
}
// ---------------------------------------------------------------------------------------------- 1. the frame worker
function workerPipe(worker, options) {
  // a stream of fake encoded frames in, whatever the worker lets through out
  let push;
  const readable = new ReadableStream({ start(c) { push = c; } });
  const got = [];
  const writable = new WritableStream({ write(frame) { got.push(frame); } });
  worker.postMessage({ type: "stream", readable, writable, options }, [readable, writable]);
  return { send: (frame) => push.enqueue(frame), got };
}

async function frameTests() {
  const call = "T".repeat(22);
  const a = new Worker(new URL("../app/callworker.js", import.meta.url));
  const b = new Worker(new URL("../app/callworker.js", import.meta.url));
  const e = new Worker(new URL("../app/callworker.js", import.meta.url));
  a.postMessage({ type: "init", call, self: "alice|devA0001" });
  b.postMessage({ type: "init", call, self: "bob|devB0001" });
  e.postMessage({ type: "init", call, self: "eve|devE0001" });
  const key = C.random(32), other = C.random(32);
  const enc = workerPipe(a, { dir: "send", stream: "cam", peer: "bob|devB0001" });
  const dec = workerPipe(b, { dir: "recv", peer: "alice|devA0001" });
  const eve = workerPipe(e, { dir: "recv", peer: "alice|devA0001" });
  const frame = (n, type) => ({ type, data: new Uint8Array(Array.from({ length: n }, (_, i) => (i * 7 + 3) & 255)).buffer });

  enc.send(frame(500, "key"));
  await sleep(300);
  log(enc.got.length === 0, "nothing leaves before there is a key", enc.got.length + " frames out");

  a.postMessage({ type: "sendKey", epoch: 0, key: key.slice().buffer });
  b.postMessage({ type: "recvKey", peer: "alice|devA0001", epoch: 0, key: key.slice().buffer });
  e.postMessage({ type: "recvKey", peer: "alice|devA0001", epoch: 0, key: other.slice().buffer });
  enc.send(frame(1200, "key")); enc.send(frame(300, "delta")); enc.send(frame(40, "delta"));
  await until(() => enc.got.length === 3, 3000);
  const sealed = enc.got.map((f) => new Uint8Array(f.data));
  log(sealed.length === 3 && sealed[0].length === 1200 + 16 + 12, "frames are sealed (tag + 12-byte trailer)", sealed.map((s) => s.length).join(","));
  const plain0 = new Uint8Array(frame(1200, "key").data);
  log(sealed[0].subarray(0, 10).every((x, i) => x === plain0[i]) && !sealed[0].subarray(10, 60).every((x, i) => x === plain0[10 + i]),
      "VP8 header bytes stay clear, the rest is ciphertext");

  for (const s of sealed) dec.send({ type: "delta", data: s.slice().buffer });       // the receiver's own idea of the frame type must not matter
  await until(() => dec.got.length === 3, 3000);
  const opened = dec.got.map((f) => new Uint8Array(f.data));
  const same = (x, y) => x.length === y.length && x.every((v, i) => v === y[i]);
  log(opened.length === 3 && same(opened[0], plain0) && same(opened[1], new Uint8Array(frame(300, "delta").data)), "the receiver gets exactly the original frames");

  const t = sealed[2].slice(); t[20] ^= 1;                                         // one bit changed
  dec.send({ type: "delta", data: t.buffer });
  const t2 = sealed[2].slice(); t2[t2.length - 2] = 1;                             // the trailer's clear length changed
  dec.send({ type: "delta", data: t2.buffer });
  await sleep(500);
  log(dec.got.length === 3, "a tampered and a re-labelled frame are both dropped", dec.got.length + " delivered");

  // freshness: once 600 newer frames have arrived, an old one is refused even though it is authentic
  const old = sealed[1].slice();
  const fresh = [];
  for (let i = 0; i < 600; i++) enc.send(frame(30, "delta"));
  await until(() => enc.got.length === 603, 8000);
  for (const f of enc.got.slice(3)) dec.send({ type: "delta", data: new Uint8Array(f.data).slice().buffer });
  await until(() => dec.got.length === 603, 8000);
  dec.send({ type: "delta", data: old.buffer });
  await sleep(400);
  log(dec.got.length === 603, "an authentic but stale frame is refused", (dec.got.length - 603) + " extra delivered");
  void fresh;

  for (const s of sealed) eve.send({ type: "delta", data: s.slice().buffer });
  await sleep(500);
  log(eve.got.length === 0, "a receiver with another key gets nothing", eve.got.length + " delivered");

  // a frame made for bob can't be replayed to carol: the key is per link
  const c2 = new Worker(new URL("../app/callworker.js", import.meta.url));
  c2.postMessage({ type: "init", call, self: "carol|devC0001" });
  c2.postMessage({ type: "recvKey", peer: "alice|devA0001", epoch: 0, key: key.slice().buffer });
  const carol = workerPipe(c2, { dir: "recv", peer: "alice|devA0001" });
  for (const s of sealed) carol.send({ type: "delta", data: s.slice().buffer });
  await sleep(500);
  log(carol.got.length === 0, "frames for one person can't be replayed to another, even with the sender's key", carol.got.length + " delivered");
  for (const w of [a, b, e, c2]) w.terminate();
}

// ---------------------------------------------------------------------------------------------- 2. whole calls
async function person(user) {
  const id = await C.identityFromMaster(user, C.random(32));
  const pubEntry = await C.publishIdentity(id, Date.now());
  const pub = await C.openIdentity({ b: pubEntry.bundle.b, s: pubEntry.bundle.s }, user);
  return { user, id, fp: pubEntry.fp, pub };
}

// a camera and microphone made in the page: a moving picture (drawn on a timer, so it runs in a background tab) and a tone
function fakeMedia(colour) {
  const canvas = document.createElement("canvas");
  canvas.width = 640; canvas.height = 360;
  const g = canvas.getContext("2d");
  let n = 0;
  setInterval(() => { n++; g.fillStyle = colour; g.fillRect(0, 0, 640, 360); g.fillStyle = "#fff"; g.fillRect((n * 9) % 640, 150, 60, 60); }, 66);
  const ac = new AudioContext();
  const o = ac.createOscillator(), dst = ac.createMediaStreamDestination();
  o.connect(dst); o.start();
  return () => new MediaStream([...canvas.captureStream(15).getVideoTracks(), ...dst.stream.getAudioTracks()]);
}

async function callTests() {
  const alice = await person("alice"), bob = await person("bob"), eve = await person("eve");
  const directory = { alice, bob };                                  // eve is NOT trusted by anyone
  const engines = {};
  let sid = 0;
  const events = { alice: [], bob: [] };
  const media = { alice: fakeMedia("#0b5c58"), bob: fakeMedia("#5c0b4a") };
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  let current = "alice";
  navigator.mediaDevices.getUserMedia = async () => media[current]();

  function hostFor(p) {
    const dev = "dev" + p.user.toUpperCase() + "00001".slice(0, 9 - p.user.length);
    const trusted = (u) => (directory[u] ? { pub: directory[u].pub, fp: directory[u].fp } : null);
    return Object.assign(webHost(p.id, p.fp, dev, trusted), {
      user: p.user, dev, trusted,
      api: async (path, body) => {
        if (path === "calls/turn") return { ice_servers: [], relay_only: false };
        if (path !== "calls/signal") throw new Error("unexpected " + path);
        const hdr = JSON.parse(new TextDecoder().decode(C.unb64(body.sig.h)));
        const item = { sid: ++sid, room: body.room, from: p.user, at: Date.now() / 1000, kind: hdr.kind, call: hdr.call, sig: body.sig };
        for (const u of body.to) if (engines[u]) setTimeout(() => { current = u; engines[u].handleSignals([item]); }, 5);
        return { ok: true, sid };
      },
      onEvent: (type, d) => events[p.user] && events[p.user].push([type, d]),
    });
  }
  engines.alice = new CallEngine(hostFor(alice));
  engines.bob = new CallEngine(hostFor(bob));
  log(engines.alice.cap.ok, "this browser can encrypt call media", engines.alice.cap.api || engines.alice.cap.why);
  if (!engines.alice.cap.ok) return;

  // eve (untrusted) rings bob: nothing happens
  const eveHost = hostFor(eve);
  const eveSig = await (await import("../app/callcrypto.js")).sealSignal(eve.id, eve.fp, { kind: "ring", room: "r".repeat(16), call: "E".repeat(22), dev: "devEVE001", to: ["bob"], media: "video", people: ["eve", "bob"] });
  await engines.bob.handleSignals([{ sid: 999, room: "r".repeat(16), from: "eve", at: 0, kind: "ring", call: "E".repeat(22), sig: eveSig }]);
  log(!events.bob.some(([t]) => t === "ring"), "a ring from an identity you don't trust is ignored");
  void eveHost;

  current = "alice";
  await engines.alice.start("r".repeat(16), "video", ["bob"]);
  const rang = await until(() => events.bob.some(([t]) => t === "ring"), 5000);
  log(rang, "bob's device rings");
  const ring = events.bob.find(([t]) => t === "ring");
  current = "bob";
  await engines.bob.accept(ring[1].call);
  const connected = await until(() => {
    const pa = [...(engines.alice.call ? engines.alice.call.peers.values() : [])][0];
    const pb = [...(engines.bob.call ? engines.bob.call.peers.values() : [])][0];
    return pa && pb && pa.status === "connected" && pb.status === "connected";
  }, 20000);
  log(connected, "the two connect (WebRTC, loopback)");

  async function decoded(engine) {
    const p = [...engine.call.peers.values()][0];
    const r = await p.pc.getStats();
    let frames = 0, w = 0, audio = 0;
    r.forEach((x) => {
      if (x.type === "inbound-rtp" && x.kind === "video") { frames += x.framesDecoded || 0; w = Math.max(w, x.frameWidth || 0); }
      if (x.type === "inbound-rtp" && x.kind === "audio") audio += x.packetsReceived || 0;
    });
    return { frames, w, audio };
  }
  const flowing = await until(async () => { const a = await decoded(engines.alice), b = await decoded(engines.bob); return a.frames > 5 && b.frames > 5; }, 30000, 500);
  const da = await decoded(engines.alice), db = await decoded(engines.bob);
  log(flowing, "both decode each other's end-to-end encrypted video", "alice " + da.frames + " frames " + da.w + "px, bob " + db.frames + " frames " + db.w + "px");
  log(da.audio > 0 && db.audio > 0, "audio packets flow both ways", da.audio + " / " + db.audio);
  await sleep(2500);
  const fs = engines.bob.frameStats || {};
  log(fs.received > 0 && fs.failed === 0, "every frame bob received decrypted", JSON.stringify(fs));
  log(engines.alice.call.words.join(" ") === engines.bob.call.words.join(" "), "both see the same call words", engines.alice.call.words.join(" "));

  // bob's receive keys disappear (as for someone who was never given them): his decoder gets nothing more
  const before = (await decoded(engines.bob)).frames;
  engines.bob.worker.postMessage({ type: "forget", peer: "alice|" + hostFor(alice).dev });
  await sleep(1500);
  const mid = (await decoded(engines.bob)).frames;
  await sleep(2500);
  const after = (await decoded(engines.bob)).frames;
  log(after - mid <= 1, "without the key nothing decodes: the media really is encrypted", "frames " + before + " -> " + mid + " -> " + after);

  // key rotation: alice rotates, bob keeps decoding (he gets her new key)
  await engines.alice.rotate();
  await sleep(1500);
  const r1 = (await decoded(engines.alice)).frames;
  await sleep(2000);
  log((await decoded(engines.alice)).frames > r1, "after alice's key rotation, she still decodes bob (and he gets her new key)");

  // in-call extras: a reaction and a raised hand reach the other side (signed "state" signals)
  current = "alice";
  engines.alice.react("🎉");
  engines.alice.raiseHand(true);
  const gotReaction = await until(() => events.bob.some(([t, d]) => t === "state" && d.reaction === "🎉"), 5000);
  const gotHand = await until(() => events.bob.some(([t, d]) => t === "state" && d.peer && d.peer.remote.hand), 5000);
  log(gotReaction && gotHand, "a reaction and a raised hand reach the other person");

  // screen sharing: a third encrypted stream through the same path the share button uses
  const screen = document.createElement("canvas");
  screen.width = 1280; screen.height = 720;
  const sg = screen.getContext("2d");
  let sn = 0;
  const st = setInterval(() => { sn++; sg.fillStyle = "#222"; sg.fillRect(0, 0, 1280, 720); sg.fillStyle = "#36d2cb"; sg.fillRect(100 + (sn * 13) % 900, 300, 120, 80); }, 66);
  const scrTrack = screen.captureStream(15).getVideoTracks()[0];
  engines.alice.call.local.scr = scrTrack; engines.alice.call.local.scrOn = true;
  engines.alice.replace("scr", scrTrack);
  engines.alice.broadcastState();
  const shared = await until(async () => {
    const p = [...engines.bob.call.peers.values()][0];
    const r = await p.pc.getStats();
    let decoded = 0;
    r.forEach((x) => { if (x.type === "inbound-rtp" && x.kind === "video" && x.mid === "2") decoded = x.framesDecoded || 0; });
    return decoded > 3 && p.streams.scr.getVideoTracks().length > 0;
  }, 20000, 500);
  log(shared, "a shared screen arrives as its own encrypted stream");
  clearInterval(st);

  current = "bob";
  await engines.bob.hangup();
  const ended = await until(() => events.alice.some(([t]) => t === "ended"), 8000);
  log(ended, "bob hangs up; the call ends for alice (everyone left)");
  log(!engines.alice.call && !engines.bob.call, "both engines are idle and their workers wiped");
  navigator.mediaDevices.getUserMedia = real;
}

// ---------------------------------------------------------------------------------------------- 3. a group call
async function groupTests() {
  const people = {};
  for (const u of ["alice", "bob", "carol"]) people[u] = await person(u);
  const engines = {}, events = { alice: [], bob: [], carol: [] };
  const media = { alice: fakeMedia("#0b5c58"), bob: fakeMedia("#5c0b4a"), carol: fakeMedia("#4a5c0b") };
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  let current = "alice", sid = 1000;
  navigator.mediaDevices.getUserMedia = async () => media[current]();
  for (const p of Object.values(people)) {
    const dev = "dev" + p.user.toUpperCase().padEnd(6, "0");
    const trusted = (u) => (people[u] ? { pub: people[u].pub, fp: people[u].fp } : null);
    engines[p.user] = new CallEngine(Object.assign(webHost(p.id, p.fp, dev, trusted), {
      user: p.user, dev, trusted,
      api: async (path, body) => {
        if (path === "calls/turn") return { ice_servers: [], relay_only: false };
        const hdr = JSON.parse(new TextDecoder().decode(C.unb64(body.sig.h)));
        const item = { sid: ++sid, room: body.room, from: p.user, at: 0, kind: hdr.kind, call: hdr.call, sig: body.sig };
        for (const u of body.to) setTimeout(() => { current = u; engines[u].handleSignals([item]); }, 5);
        return { ok: true, sid };
      },
      onEvent: (type, d) => events[p.user].push([type, d]),
    }));
  }
  current = "alice";
  await engines.alice.start("g".repeat(16), "video", ["bob", "carol"]);
  for (const u of ["bob", "carol"]) {
    await until(() => events[u].some(([t]) => t === "ring"), 5000);
    current = u;
    await engines[u].accept(events[u].find(([t]) => t === "ring")[1].call);
  }
  const mesh = await until(() => ["alice", "bob", "carol"].every((u) => engines[u].call && engines[u].call.peers.size === 2 &&
    [...engines[u].call.peers.values()].every((p) => p.status === "connected")), 30000, 250);
  log(mesh, "three people: everyone connects to everyone (mesh)",
      ["alice", "bob", "carol"].map((u) => u + ":" + (engines[u].call ? [...engines[u].call.peers.values()].map((p) => p.status).join("/") : "-")).join(" "));
  const decodesAll = await until(async () => {
    for (const u of ["alice", "bob", "carol"]) {
      for (const p of engines[u].call.peers.values()) {
        const r = await p.pc.getStats();
        let f = 0;
        r.forEach((x) => { if (x.type === "inbound-rtp" && x.kind === "video" && x.mid === "1") f = x.framesDecoded || 0; });
        if (f < 3) return false;
      }
    }
    return true;
  }, 40000, 1000);
  log(decodesAll, "each of the three decodes both others' encrypted video");
  const words = ["alice", "bob", "carol"].map((u) => engines[u].call.words.join(" "));
  log(new Set(words).size === 1, "all three see the same call words", words[0]);
  const epochBefore = engines.alice.call.epoch;
  current = "carol";
  await engines.carol.hangup();
  const left = await until(() => engines.alice.call && engines.alice.call.peers.size === 1 && engines.bob.call && engines.bob.call.peers.size === 1, 8000);
  log(left && engines.alice.call.epoch > epochBefore, "carol leaves; alice and bob carry on with a fresh key", "epoch " + epochBefore + " -> " + (engines.alice.call && engines.alice.call.epoch));
  for (const u of ["alice", "bob"]) { current = u; await engines[u].hangup(); }
  navigator.mediaDevices.getUserMedia = real;
}

(async () => {
  try { await fixtureTests(); } catch (e) { log(false, "Windows fixture tests crashed", e.message); }
  try { await frameTests(); } catch (e) { log(false, "frame tests crashed", e.message); }
  try { await callTests(); } catch (e) { log(false, "call tests crashed", e.stack || e.message); }
  try { await groupTests(); } catch (e) { log(false, "group call tests crashed", e.stack || e.message); }
  results.done = true;
  out.textContent += "\n" + results.pass + " passed, " + results.fail + " failed\n";
})();
