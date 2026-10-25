// Crypto check page (/admin/chat/selftest.html): runs the chat's built-in self-test, then the whole protocol end to
// end with throwaway identities, including the tamper cases that must fail. Nothing is sent anywhere. It also prints
// a fresh ML-KEM ciphertext and ML-DSA signature for checking against OpenSSL (docs/CHAT.md, "Interop check").
import * as C from "./crypto.js";
import { KAT } from "./kat.js";
import { ml_kem1024 } from "./vendor/post-quantum/ml-kem.js";
import { ml_dsa87 } from "./vendor/post-quantum/ml-dsa.js";

const FILE_CHUNK_SEALED = C.FILE_CHUNK + 16;
const utf8Bytes = (s) => new TextEncoder().encode(s);
const out = document.getElementById("st-out");
const summary = document.getElementById("st-summary");
let pass = 0, fail = 0;

function line(ok, name, extra) {
  const row = document.createElement("div");
  row.className = ok ? "st-ok" : "st-bad";
  row.textContent = (ok ? "[ OK ] " : "[FAIL] ") + name + (extra ? "  " + extra : "");
  out.appendChild(row);
  ok ? pass++ : fail++;
}
async function expectFail(name, fn) {
  try { await fn(); line(false, name, "(was accepted)"); } catch (e) { line(e instanceof C.CryptoFail, name, e instanceof C.CryptoFail ? "" : "(" + e + ")"); }
}
async function timed(fn) { const t = performance.now(); const r = await fn(); return [r, Math.round(performance.now() - t) + " ms"]; }

async function run() {
  try {
    (await C.selfTest()).forEach((r) => line(r.ok, r.name));
  } catch (e) { line(false, String(e.message || e)); }

  const [owner, t1] = await timed(() => C.identityFromMaster("dcx-admin", C.random(32)));
  const alice = await C.identityFromMaster("alice", C.random(32));
  line(true, "identities derived from a master secret", t1);
  const o = await C.publishIdentity(owner, Date.now());
  const a = await C.publishIdentity(alice, Date.now());
  const again = await C.publishIdentity(await C.identityFromMaster("alice", C.random(32)), Date.now());
  line(o.fp.length === 64 && a.fp !== again.fp, "fingerprints are SHA3-256 of the published identity");
  const ownerPub = await C.openIdentity({ b: o.bundle.b, s: o.bundle.s, fp: o.fp }, "dcx-admin");
  const alicePub = await C.openIdentity({ b: a.bundle.b, s: a.bundle.s, fp: a.fp }, "alice");
  line(alicePub.fp === a.fp, "published identity verifies (self-signature)");
  await expectFail("identity claimed for another user is refused", () => C.openIdentity(a.bundle, "bob"));
  await expectFail("identity with someone else's signature is refused", () => C.openIdentity({ b: a.bundle.b, s: o.bundle.s }, "alice"));
  const master2 = C.random(32);
  const r1 = await C.publishIdentity(await C.identityFromMaster("carol", master2), 1);
  const r2 = await C.publishIdentity(await C.identityFromMaster("carol", master2), 1);
  line(r1.fp === r2.fp, "same master secret gives the same identity (new device restore)");

  const cert = await C.makeCert(owner, o.fp, "alice", a.fp, Date.now());
  line(await C.verifyCert(cert, ownerPub, "alice", a.fp), "owner certificate verifies");
  line(!(await C.verifyCert(cert, ownerPub, "alice", again.fp)), "certificate doesn't cover a different identity");
  const fake = await C.makeCert(alice, a.fp, "alice", a.fp, Date.now());
  line(!(await C.verifyCert(fake, ownerPub, "alice", a.fp)), "a certificate not signed by the owner is refused");
  line(C.safetyNumber(o.fp, a.fp) === C.safetyNumber(a.fp, o.fp) && /^(\d{5} ){11}\d{5}$/.test(C.safetyNumber(o.fp, a.fp)),
    "safety number is the same from both sides (60 digits)");

  const pepper = C.random(32);
  const payload = { v: 1, master: C.b64(C.random(32)), anchor_fp: o.fp };
  const [sealed, t2] = await timed(() => C.sealBackup("alice", "correct horse battery staple 42", pepper, 1, payload));
  line(true, "passphrase backup sealed (Argon2id 64 MiB, 3 passes)", t2);
  const [opened, t3] = await timed(() => C.openBackup("alice", "correct horse battery staple 42", pepper, sealed));
  line(opened.master === payload.master && opened.anchor_fp === o.fp, "passphrase backup opens", t3);
  await expectFail("wrong passphrase is refused", () => C.openBackup("alice", "correct horse battery staple 43", pepper, sealed));
  await expectFail("wrong server key share is refused", () => C.openBackup("alice", "correct horse battery staple 42", C.random(32), sealed));
  await expectFail("backup moved to another account is refused", () => C.openBackup("mallory", "correct horse battery staple 42", pepper, sealed));
  await expectFail("weakened passphrase settings are refused", () => C.openBackup("alice", "x", pepper, Object.assign({}, sealed, { kdf: Object.assign({}, sealed.kdf, { m: 1024 }) })));

  const room = "0123456789abcdef";
  const rcpts = [{ u: "alice", fp: a.fp, pub: alicePub }, { u: "dcx-admin", fp: o.fp, pub: ownerPub }];
  const [ep, t4] = await timed(() => C.buildEpoch(owner, o.fp, room, 1, rcpts, ""));
  line(Object.keys(ep.pkg.w).length === 2, "room key wrapped for 2 members", t4);
  const item = (w) => ({ room, epoch: 1, from: "dcx-admin", body: { h: ep.pkg.h, s: ep.pkg.s, w } });
  const [got, t5] = await timed(() => C.openEpoch(alice, a.fp, room, item(ep.pkg.w.alice), ownerPub));
  line(C.hex(got.key) === C.hex(ep.key), "member unwraps the room key (and its commitment matches)", t5);
  await expectFail("someone else's wrapped copy is refused", () => C.openEpoch(alice, a.fp, room, item(ep.pkg.w["dcx-admin"]), ownerPub));
  await expectFail("room key signed by a non-member identity is refused", () => C.openEpoch(alice, a.fp, room, item(ep.pkg.w.alice), alicePub));
  await expectFail("room key replayed into another room is refused", () => C.openEpoch(alice, a.fp, "fedcba9876543210", Object.assign(item(ep.pkg.w.alice), { room: "fedcba9876543210" }), ownerPub));
  for (const [at, part] of [[5, "ML-KEM ciphertext"], [1580, "X25519 ephemeral key"], [1640, "AES-GCM part"]]) {
    const flipped = C.unb64(ep.pkg.w.alice); flipped[at] ^= 1;
    await expectFail("changed wrapped key (" + part + ") is refused", () => C.openEpoch(alice, a.fp, room, item(C.b64(flipped)), ownerPub));
    const body = { h: ep.pkg.h, s: ep.pkg.s, w: C.b64(flipped) };      // even with the header hash check skipped:
    await expectFail("  ...and fails to unwrap on its own (" + part + ")", () => C.unwrapKey(flipped, alice,
      C.utf8("dcx-chat/v1/wrap|" + room + "|1|alice|" + a.fp)).then(() => body));
  }

  const [m, t6] = await timed(() => C.sealMessage(alice, a.fp, room, 1, got.key, { k: "text", text: "hello from alice ✓" }));
  const mi = { room, epoch: 1, from: "alice", body: m };
  const [om, t7] = await timed(() => C.openMessage(mi, ep.key, alicePub));
  line(om.payload.text === "hello from alice ✓", "message sealed and opened", "seal " + t6 + ", open " + t7);
  line(C.unb64(m.c).length === 12 + 256 + 16, "short message padded to the 256-byte bucket");
  const ct = C.unb64(m.c); ct[20] ^= 1;
  await expectFail("changed ciphertext is refused", () => C.openMessage({ room, epoch: 1, from: "alice", body: Object.assign({}, m, { c: C.b64(ct) }) }, ep.key, alicePub));
  await expectFail("message claimed by another sender is refused", () => C.openMessage(Object.assign({}, mi, { from: "dcx-admin" }), ep.key, ownerPub));
  await expectFail("message under the wrong room key is refused", () => C.openMessage(mi, C.random(32), alicePub));
  await expectFail("message moved to another epoch is refused", () => C.openMessage(Object.assign({}, mi, { epoch: 2 }), ep.key, alicePub));

  // Attachments: per-file key, 64 KiB chunks, index + last-chunk flag bound in, hash in the signed message
  const big = C.random(200000);
  const [sealedFile, t8] = await timed(() => C.sealFile(big));
  line(sealedFile.sealed.length === 4 * (C.FILE_CHUNK + 16), "200 KB file sealed as 4 padded chunks", t8);
  line(C.hex((await C.openFile(sealedFile.sealed, sealedFile.key, sealedFile.size, sealedFile.sha3))) === C.hex(big), "attachment opens to the exact bytes");
  const swapped = C.concat(sealedFile.sealed.slice(FILE_CHUNK_SEALED, 2 * FILE_CHUNK_SEALED), sealedFile.sealed.slice(0, FILE_CHUNK_SEALED), sealedFile.sealed.slice(2 * FILE_CHUNK_SEALED));
  const sha = async (b) => C.hex((await import("./vendor/hashes/sha3.js")).sha3_256(b));
  await expectFail("attachment with reordered chunks is refused", async () => C.openFile(swapped, sealedFile.key, sealedFile.size, await sha(swapped)));
  const dropped = sealedFile.sealed.slice(0, 3 * FILE_CHUNK_SEALED);
  await expectFail("attachment with its last chunk dropped is refused", async () => C.openFile(dropped, sealedFile.key, 3 * C.FILE_CHUNK, await sha(dropped)));
  await expectFail("attachment that doesn't match its signed hash is refused", () => C.openFile(sealedFile.sealed, sealedFile.key, sealedFile.size, "0".repeat(64)));
  await expectFail("attachment under another key is refused", async () => C.openFile(sealedFile.sealed, C.b64(C.random(32)), sealedFile.size, sealedFile.sha3));
  const reactMsg = await C.sealMessage(alice, a.fp, room, 1, got.key, { k: "react", text: "", target: m.h ? JSON.parse(atob(m.h)).id : "", emoji: "👍", on: true });
  line((await C.openMessage({ room, epoch: 1, from: "alice", body: reactMsg }, ep.key, alicePub)).payload.emoji === "👍", "reaction is a signed, encrypted message");
  const badKind = await C.sealMessage(alice, a.fp, room, 1, got.key, { k: "script", text: "x" });
  await expectFail("unknown message kinds are refused", () => C.openMessage({ room, epoch: 1, from: "alice", body: badKind }, ep.key, alicePub));
  const badFile = await C.sealMessage(alice, a.fp, room, 1, got.key, { k: "file", text: "", files: [{ blob: "x", name: "a", mime: "a", kind: "image", size: 1, sha3: "0", key: "k" }] });
  await expectFail("malformed attachment references are refused", () => C.openMessage({ room, epoch: 1, from: "alice", body: badFile }, ep.key, alicePub));
  line(C.sniff(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 0])) === "image/png" && C.sniff(utf8Bytes("<svg onload=x>")) === "application/octet-stream",
    "pictures are recognised by their bytes (SVG/HTML never shown inline)");

  // Interop material for OpenSSL (seeded KAT keys): see docs/CHAT.md
  const seed = C.fromHex(KAT.seed32);
  const kk = ml_kem1024.keygen(C.concat(seed, seed));
  const encp = ml_kem1024.encapsulate(kk.publicKey);
  const dk = ml_dsa87.keygen(seed);
  const sig = ml_dsa87.sign(C.utf8(KAT.mldsa87_msg), dk.secretKey, { context: C.utf8(KAT.mldsa87_context) });
  document.getElementById("st-interop").textContent =
    "kem_ct_b64=" + C.b64(encp.cipherText) + "\nkem_ss=" + C.hex(encp.sharedSecret) + "\ndsa_sig_b64=" + C.b64(sig) + "\n";

  summary.textContent = fail ? fail + " check(s) FAILED, " + pass + " passed. Don't use the chat in this browser." : "All " + pass + " checks passed.";
  summary.className = fail ? "st-bad" : "st-ok";
  document.body.setAttribute("data-done", fail ? "fail" : "pass");
}
run().catch((e) => { line(false, "unexpected error: " + (e && e.message || e)); summary.textContent = "Self-test crashed."; document.body.setAttribute("data-done", "fail"); });
