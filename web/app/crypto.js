// CipherChat: every cryptographic operation, in one small module with no DOM or network access.
//
// Hybrid post-quantum throughout: each public-key step combines a NIST post-quantum algorithm with a classical one,
// so it stays secure as long as EITHER holds (a flaw found in a new PQ scheme doesn't expose anything, and neither
// does a quantum computer breaking the curves).
//   key wrapping   ML-KEM-1024 (FIPS 203) + X25519, both secrets and the whole transcript through HKDF-SHA-512
//   signatures     ML-DSA-87 (FIPS 204, with a context string) + Ed25519; a signature is valid only if BOTH verify
//   symmetric      AES-256-GCM, a fresh HKDF-SHA-512 key per message; SHA3-256/512 for fingerprints and commitments
//   passphrase     Argon2id (64 MiB, 3 passes) mixed with a per-user server key share
// ML-KEM, ML-DSA, SHA-3 and Argon2id come from the vendored, pinned @noble libraries (vendor/VENDOR.json); X25519,
// Ed25519, HKDF and AES-GCM are the browser's own WebCrypto. Protocol and threat model: docs/CHAT.md.
import { ml_kem1024 } from "./vendor/post-quantum/ml-kem.js";
import { ml_dsa87 } from "./vendor/post-quantum/ml-dsa.js";
import { sha3_256, sha3_512 } from "./vendor/hashes/sha3.js";
import { argon2idAsync } from "./vendor/hashes/argon2.js";
import { KAT } from "./kat.js";

const subtle = globalThis.crypto && globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export const SUITE = "ML-KEM-1024+X25519 / ML-DSA-87+Ed25519 / AES-256-GCM / SHA-3";
export const SIZES = { kemPq: 1568, kemEc: 32, sigPq: 2592, sigEc: 32, kemCt: 1568, sigPqLen: 4627, sigEcLen: 64,
                       wrap: 1568 + 32 + 12 + 32 + 16 };
export const KDF = { alg: "argon2id", m: 65536, t: 3, p: 1 };          // m in KiB (64 MiB)
const PAD_BUCKETS = [256, 1024, 4096, 16384];
export const MAX_TEXT_BYTES = PAD_BUCKETS[PAD_BUCKETS.length - 1] - 4 - 64;

export class CryptoFail extends Error {}

// ---------------------------------------------------------------------------------------------- bytes
export const utf8 = (s) => enc.encode(s);
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
export function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
export function unb64(str, size) {
  if (typeof str !== "string" || str.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(str)) throw new CryptoFail("malformed base64");
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (size !== undefined && out.length !== size) throw new CryptoFail("wrong length");
  return out;
}
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function random(n) {                    // getRandomValues fills at most 64 KiB per call
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(out.subarray(o, Math.min(n, o + 65536)));
  return out;
}
function u32be(n) { return new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }
function wipe(...arrs) { arrs.forEach((a) => a && a.fill && a.fill(0)); }
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// Canonical JSON: keys sorted at every level, no spaces. Everything signed is canonical bytes, sent as base64, so
// the bytes that were signed are exactly the bytes that get verified (nobody re-serialises).
export function canon(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new CryptoFail("only whole numbers are signed");
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  throw new CryptoFail("unsignable value");
}
export const canonBytes = (v) => utf8(canon(v));
export function parseSigned(b64str, maxLen) {
  const raw = unb64(b64str);
  if (raw.length > maxLen) throw new CryptoFail("too large");
  let obj;
  try { obj = JSON.parse(dec.decode(raw)); } catch (e) { throw new CryptoFail("malformed header"); }
  if (!obj || typeof obj !== "object" || Array.isArray(obj) || obj.v !== 1) throw new CryptoFail("unsupported version");
  if (canon(obj) !== dec.decode(raw)) throw new CryptoFail("header is not canonical");
  return { raw, obj };
}

// ---------------------------------------------------------------------------------------------- WebCrypto pieces
const PKCS8 = { Ed25519: "302e020100300506032b657004220420", X25519: "302e020100300506032b656e04220420" };
export function fromHex(h) { return new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16))); }
function b64urlToBytes(s) { return unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4)); }

// A 32-byte seed -> {priv: non-extractable CryptoKey, pub: raw 32 bytes}
async function curveFromSeed(alg, seed) {
  const usage = alg === "Ed25519" ? ["sign"] : ["deriveBits"];
  const tmp = await subtle.importKey("pkcs8", concat(fromHex(PKCS8[alg]), seed), { name: alg }, true, usage);
  const jwk = await subtle.exportKey("jwk", tmp);
  const pub = b64urlToBytes(jwk.x);
  const priv = await subtle.importKey("pkcs8", concat(fromHex(PKCS8[alg]), seed), { name: alg }, false, usage);
  return { priv, pub };
}

async function hkdfKey(ikm, salt, info, usage) {
  const base = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-512", salt, info: utf8(info) }, base,
    { name: "AES-GCM", length: 256 }, false, usage);
}
async function aesSeal(key, plain, aad) {
  const nonce = random(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, plain));
  return concat(nonce, ct);
}
async function aesOpen(key, sealed, aad) {
  if (sealed.length < 12 + 16) throw new CryptoFail("ciphertext too short");
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: sealed.subarray(0, 12), additionalData: aad, tagLength: 128 },
      key, sealed.subarray(12)));
  } catch (e) {
    throw new CryptoFail("decryption failed (wrong key or the data was changed)");
  }
}

// ---------------------------------------------------------------------------------------------- identities
// One 32-byte master secret per person; every private key is derived from it with domain-separated SHA-3, so the
// sealed backup is tiny and a new device rebuilds identical keys.
function derive(master, label, len) {
  const h = (len === 64 ? sha3_512 : sha3_256)(concat(utf8("dcx-chat/v1/seed/" + label + "|"), master));
  return h;
}

export async function identityFromMaster(user, master) {
  if (!(master instanceof Uint8Array) || master.length !== 32) throw new CryptoFail("bad master secret");
  const kemSeed = derive(master, "kem-pq", 64), sigSeed = derive(master, "sig-pq", 32);
  const kem = ml_kem1024.keygen(kemSeed);
  const sig = ml_dsa87.keygen(sigSeed);
  const x = await curveFromSeed("X25519", derive(master, "kem-ec", 32));
  const ed = await curveFromSeed("Ed25519", derive(master, "sig-ec", 32));
  wipe(kemSeed, sigSeed);
  return {
    user,
    kemPq: { pk: kem.publicKey, sk: kem.secretKey }, kemEc: x,
    sigPq: { pk: sig.publicKey, sk: sig.secretKey }, sigEc: ed,
  };
}

// The signed public half that everyone else uses. Returns {bundle: {b, s}, fp}.
export async function publishIdentity(id, at) {
  const obj = { v: 1, t: "identity", user: id.user, at, kem_pq: b64(id.kemPq.pk), kem_ec: b64(id.kemEc.pub),
                sig_pq: b64(id.sigPq.pk), sig_ec: b64(id.sigEc.pub) };
  const raw = canonBytes(obj);
  const s = await sign(id, "dcx-chat/v1/identity", raw);
  return { bundle: { b: b64(raw), s: b64(s) }, fp: hex(sha3_256(raw)) };
}

// Someone else's published identity -> verified public keys (throws if anything is off). Checks the self-signature
// (proof they hold the private keys); WHO it belongs to comes from the owner's certificate (verifyCert).
export async function openIdentity(entry, expectUser) {
  const { raw, obj } = parseSigned(entry.b, 16384);
  if (obj.t !== "identity" || obj.user !== expectUser) throw new CryptoFail("identity is for someone else");
  const fp = hex(sha3_256(raw));
  if (entry.fp !== undefined && entry.fp !== fp) throw new CryptoFail("fingerprint mismatch");
  const pub = {
    user: obj.user, fp, at: obj.at,
    kemPq: unb64(obj.kem_pq, SIZES.kemPq), kemEc: unb64(obj.kem_ec, SIZES.kemEc),
    sigPq: unb64(obj.sig_pq, SIZES.sigPq), sigEc: unb64(obj.sig_ec, SIZES.sigEc),
  };
  pub.sigEcKey = await subtle.importKey("raw", pub.sigEc, { name: "Ed25519" }, false, ["verify"]);
  if (!(await verify(pub, "dcx-chat/v1/identity", raw, unb64(entry.s)))) throw new CryptoFail("identity self-signature is invalid");
  return pub;
}

// ---------------------------------------------------------------------------------------------- hybrid signatures
export async function sign(id, label, msg) {
  const s1 = ml_dsa87.sign(msg, id.sigPq.sk, { context: utf8(label) });     // hedged (fresh randomness each time)
  const s2 = new Uint8Array(await subtle.sign({ name: "Ed25519" }, id.sigEc.priv, concat(utf8(label), new Uint8Array([0]), msg)));
  return concat(s1, s2);
}
export async function verify(pub, label, msg, sig) {
  if (!(sig instanceof Uint8Array) || sig.length !== SIZES.sigPqLen + SIZES.sigEcLen) return false;
  let pq = false;
  try { pq = ml_dsa87.verify(sig.subarray(0, SIZES.sigPqLen), msg, pub.sigPq, { context: utf8(label) }); } catch (e) { pq = false; }
  const key = pub.sigEcKey || await subtle.importKey("raw", pub.sigEc, { name: "Ed25519" }, false, ["verify"]);
  let ec = false;
  try { ec = await subtle.verify({ name: "Ed25519" }, key, sig.subarray(SIZES.sigPqLen), concat(utf8(label), new Uint8Array([0]), msg)); } catch (e) { ec = false; }
  return pq === true && ec === true;                                       // BOTH, never either
}

// ---------------------------------------------------------------------------------------------- hybrid key wrapping
// Wraps a 32-byte key for one recipient. Output: ML-KEM ct (1568) || X25519 ephemeral (32) || nonce (12) || GCM (48).
export async function wrapKey(key32, rcpt, aad) {
  const enc1 = ml_kem1024.encapsulate(rcpt.kemPq);
  const ssPq = Uint8Array.from(enc1.sharedSecret);
  const ct = enc1.cipherText;
  const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const rKey = await subtle.importKey("raw", rcpt.kemEc, { name: "X25519" }, false, []);
  const ssEc = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: rKey }, eph.privateKey, 256));
  if (ssEc.every((x) => x === 0)) throw new CryptoFail("recipient X25519 key is invalid");
  const wk = await wrapKdf(ssPq, ssEc, ct, ephPub, rcpt);
  wipe(ssPq, ssEc);
  const sealed = await aesSeal(wk, key32, aad);
  return concat(ct, ephPub, sealed);
}
export async function unwrapKey(wrapped, id, aad) {
  if (wrapped.length !== SIZES.wrap) throw new CryptoFail("wrapped key has the wrong length");
  const ct = wrapped.subarray(0, 1568), ephPub = wrapped.subarray(1568, 1600), sealed = wrapped.subarray(1600);
  const ssPq = Uint8Array.from(ml_kem1024.decapsulate(ct, id.kemPq.sk));   // implicit rejection: wrong ct -> random ss -> GCM fails
  const eKey = await subtle.importKey("raw", ephPub, { name: "X25519" }, false, []);
  const ssEc = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: eKey }, id.kemEc.priv, 256));
  if (ssEc.every((x) => x === 0)) throw new CryptoFail("invalid ephemeral key");
  const wk = await wrapKdf(ssPq, ssEc, ct, ephPub, { kemPq: id.kemPq.pk, kemEc: id.kemEc.pub });
  wipe(ssPq, ssEc);
  const key = await aesOpen(wk, sealed, aad);
  if (key.length !== 32) throw new CryptoFail("wrapped key has the wrong length");
  return key;
}
// "KitchenSink" combiner: both shared secrets are the key material; both ciphertexts and both recipient public keys
// are bound in through the salt, so neither half can be swapped or replayed into another context.
function wrapKdf(ssPq, ssEc, ct, ephPub, rcpt) {
  const salt = sha3_512(concat(utf8("dcx-chat/v1/wrap-transcript|"), ct, ephPub, rcpt.kemPq, rcpt.kemEc));
  return hkdfKey(concat(ssPq, ssEc), salt, "dcx-chat/v1/wrap-key", ["encrypt", "decrypt"]);
}

// ---------------------------------------------------------------------------------------------- fingerprints
export function fpGroups(fp) { return fp.match(/.{4}/g).join(" "); }
// A 60-digit number both people see identically; reading it to each other proves both keys at once.
export function safetyNumber(fpA, fpB) {
  const [x, y] = [fpA, fpB].sort();
  const h = sha3_512(utf8("dcx-chat/v1/safety|" + x + "|" + y));
  const groups = [];
  for (let i = 0; i < 12; i++) {
    let n = 0;
    for (let j = 0; j < 5; j++) n = n * 256 + h[i * 5 + j];
    groups.push(String(n % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

// ---------------------------------------------------------------------------------------------- certificates
export async function makeCert(owner, ownerFp, user, fp, at) {
  const raw = canonBytes({ v: 1, t: "cert", user, fp, by: owner.user, by_fp: ownerFp, at });
  return { b: b64(raw), s: b64(await sign(owner, "dcx-chat/v1/cert", raw)) };
}
export async function verifyCert(cert, ownerPub, user, fp) {
  const { raw, obj } = parseSigned(cert.b, 1024);
  if (obj.t !== "cert" || obj.user !== user || obj.fp !== fp || obj.by !== ownerPub.user || obj.by_fp !== ownerPub.fp) return false;
  return verify(ownerPub, "dcx-chat/v1/cert", raw, unb64(cert.s));
}

// ---------------------------------------------------------------------------------------------- passphrase backup
export async function sealBackup(user, passphrase, pepper, pepperVer, payload, onProgress) {
  const salt = random(32);
  const key = await backupKey(user, passphrase, pepper, pepperVer, salt, KDF, onProgress);
  const sealed = await aesSeal(key, canonBytes(payload), utf8("dcx-chat/v1/backup|" + user + "|" + pepperVer));
  return { v: 1, kdf: { alg: KDF.alg, m: KDF.m, t: KDF.t, p: KDF.p, salt: b64(salt) }, pepper_ver: pepperVer,
           n: b64(sealed.subarray(0, 12)), c: b64(sealed.subarray(12)) };
}
export async function openBackup(user, passphrase, pepper, backup, onProgress) {
  const k = backup.kdf || {};
  if (backup.v !== 1 || k.alg !== "argon2id" || !(k.m >= 65536 && k.m <= 1048576 && k.t >= 2 && k.t <= 16 && k.p >= 1 && k.p <= 4))
    throw new CryptoFail("unsupported backup format");
  const key = await backupKey(user, passphrase, pepper, backup.pepper_ver, unb64(k.salt, 32), k, onProgress);
  const plain = await aesOpen(key, concat(unb64(backup.n, 12), unb64(backup.c)), utf8("dcx-chat/v1/backup|" + user + "|" + backup.pepper_ver))
    .catch(() => { throw new CryptoFail("wrong passphrase"); });
  const payload = JSON.parse(dec.decode(plain));
  wipe(plain);
  return payload;
}
async function backupKey(user, passphrase, pepper, pepperVer, salt, kdf, onProgress) {
  const pw = utf8(String(passphrase).normalize("NFKC"));
  const a = await argon2idAsync(pw, salt, { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: 32, maxmem: 2 ** 31,
                                            onProgress: onProgress || undefined, asyncTick: 25 });
  wipe(pw);
  const key = await hkdfKey(concat(a, pepper), salt, "dcx-chat/v1/backup-key|" + user + "|" + pepperVer, ["encrypt", "decrypt"]);
  wipe(a);
  return key;
}

// ---------------------------------------------------------------------------------------------- room keys (epochs)
const wrapAad = (room, epoch, u, fp) => utf8("dcx-chat/v1/wrap|" + room + "|" + epoch + "|" + u + "|" + fp);
const commitOf = (room, epoch, key) => hex(sha3_256(concat(utf8("dcx-chat/v1/epoch-commit|" + room + "|" + epoch + "|"), key)));
export const headerHash = (raw) => hex(sha3_256(raw));

// recipients: [{u, fp, pub}] in the server's order. Returns {pkg, key}.
export async function buildEpoch(me, myFp, room, epoch, recipients, prev) {
  const key = random(32);
  const w = {}, lines = [];
  for (const r of recipients) {
    const wrapped = await wrapKey(key, r.pub, wrapAad(room, epoch, r.u, r.fp));
    w[r.u] = b64(wrapped);
    lines.push({ u: r.u, fp: r.fp, w: hex(sha3_256(wrapped)) });
  }
  const raw = canonBytes({ v: 1, t: "epoch", room, epoch, by: me.user, by_fp: myFp, at: Date.now(), prev: prev || "",
                           recipients: lines, commit: commitOf(room, epoch, key) });
  return { pkg: { h: b64(raw), s: b64(await sign(me, "dcx-chat/v1/epoch", raw)), w }, key };
}
// item.body = {h, s, w (mine)}; signerPub = the trusted identity of header.by. Returns {key, header, raw}.
export async function openEpoch(me, myFp, room, item, signerPub) {
  const { raw, obj } = parseSigned(item.body.h, 65536);
  if (obj.t !== "epoch" || obj.room !== room || obj.epoch !== item.epoch || obj.by !== item.from || obj.by !== signerPub.user || obj.by_fp !== signerPub.fp)
    throw new CryptoFail("room key header doesn't match");
  if (!(await verify(signerPub, "dcx-chat/v1/epoch", raw, unb64(item.body.s)))) throw new CryptoFail("room key signature is invalid");
  const line = (obj.recipients || []).find((r) => r.u === me.user);
  if (!line || line.fp !== myFp || !item.body.w) throw new CryptoFail("this room key wasn't made for your current identity");
  const wrapped = unb64(item.body.w, SIZES.wrap);
  if (hex(sha3_256(wrapped)) !== line.w) throw new CryptoFail("wrapped key doesn't match the signed header");
  const key = await unwrapKey(wrapped, me, wrapAad(room, obj.epoch, me.user, myFp));
  if (commitOf(room, obj.epoch, key) !== obj.commit) throw new CryptoFail("room key commitment mismatch");
  return { key, header: obj, raw };
}

// ---------------------------------------------------------------------------------------------- messages
function pad(data) {
  const need = data.length + 4;
  const size = PAD_BUCKETS.find((b) => b >= need);
  if (!size) throw new CryptoFail("message too long");
  const out = new Uint8Array(size);              // zero padding hides the exact length
  out.set(u32be(data.length), 0);
  out.set(data, 4);
  return out;
}
function unpad(p) {
  if (p.length < 4) throw new CryptoFail("bad padding");
  const n = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  if (n > p.length - 4) throw new CryptoFail("bad padding");
  return p.subarray(4, 4 + n);
}
function msgKey(roomKey, room, epoch, id) {
  return hkdfKey(roomKey, utf8(id), "dcx-chat/v1/msg|" + room + "|" + epoch, ["encrypt", "decrypt"]);
}
const sigInput = (h, c) => concat(u32be(h.length), h, c);

export async function sealMessage(me, myFp, room, epoch, roomKey, payload) {
  const id = b64(random(16)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const h = canonBytes({ v: 1, t: "msg", room, epoch, from: me.user, from_fp: myFp, id, at: Date.now() });
  const c = await aesSeal(await msgKey(roomKey, room, epoch, id), pad(canonBytes(payload)), h);
  return { h: b64(h), c: b64(c), s: b64(await sign(me, "dcx-chat/v1/msg", sigInput(h, c))) };
}
// item.body = {h, c, s}; senderPub must be the TRUSTED identity of item.from. Returns {header, payload}.
export async function openMessage(item, roomKey, senderPub) {
  const { raw, obj } = parseSigned(item.body.h, 2048);
  if (obj.t !== "msg" || obj.room !== item.room || obj.epoch !== item.epoch || obj.from !== item.from || obj.from !== senderPub.user || obj.from_fp !== senderPub.fp)
    throw new CryptoFail("message header doesn't match");
  const c = unb64(item.body.c);
  if (!(await verify(senderPub, "dcx-chat/v1/msg", sigInput(raw, c), unb64(item.body.s)))) throw new CryptoFail("message signature is invalid");
  const plain = await aesOpen(await msgKey(roomKey, obj.room, obj.epoch, obj.id), c, raw);
  const payload = JSON.parse(dec.decode(unpad(plain)));
  if (!payload || typeof payload !== "object" || typeof payload.text !== "string") throw new CryptoFail("malformed message");
  return { header: obj, payload: checkPayload(payload) };
}

// Message payload kinds (all inside the encrypted, signed message; docs/CHAT.md "Payloads"):
//   text {text, re?}   me {text}   file {text (caption), files: [...], re?}
//   react {text: "", target: <msg id>, emoji, on}   edit {text, target}
//   any of text/me/file may carry burn: <seconds visible once opened> (a burn message)
// Unknown kinds or malformed fields are refused, so an older client never shows half a message.
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
function checkPayload(p) {
  const bad = () => { throw new CryptoFail("malformed message"); };
  if (p.re !== undefined && !(typeof p.re === "string" && ID_RE.test(p.re))) bad();
  // burn: seconds the message stays visible once opened (10-300); the server destroys it once everyone opened it
  if (p.burn !== undefined && !(Number.isSafeInteger(p.burn) && p.burn >= 10 && p.burn <= 300 && ["text", "me", "file", undefined].includes(p.k))) bad();
  switch (p.k || "text") {
    case "text": case "me": return p;
    case "react":
      if (!(typeof p.target === "string" && ID_RE.test(p.target) && typeof p.emoji === "string" && p.emoji.length >= 1 &&
            p.emoji.length <= 16 && typeof p.on === "boolean")) bad();
      return p;
    case "edit":
      if (!(typeof p.target === "string" && ID_RE.test(p.target))) bad();
      return p;
    case "file":
      if (!Array.isArray(p.files) || !p.files.length || p.files.length > 10) bad();
      for (const f of p.files) checkFileRef(f, bad);
      return p;
    default: return bad();
  }
}
function checkFileRef(f, bad) {
  const ref = (r) => r && typeof r.blob === "string" && /^[0-9a-f]{24}$/.test(r.blob) && typeof r.sha3 === "string" && /^[0-9a-f]{64}$/.test(r.sha3) &&
                     typeof r.key === "string" && /^[A-Za-z0-9+/]{43}=$/.test(r.key) && Number.isSafeInteger(r.size) && r.size >= 0 && r.size <= FILE_MAX;
  if (!f || !ref(f) || typeof f.name !== "string" || f.name.length > 200 || typeof f.mime !== "string" || f.mime.length > 100 ||
      !["image", "video", "audio", "file"].includes(f.kind)) bad();
  if (f.thumb !== undefined && !ref(f.thumb)) bad();
  for (const k of ["w", "h", "dur"]) if (f[k] !== undefined && !(Number.isSafeInteger(f[k]) && f[k] >= 0 && f[k] < 1e7)) bad();
}

// ---------------------------------------------------------------------------------------------- attachments
// Files, pictures, videos and GIFs: a fresh random AES-256 key per file (sent inside the signed, encrypted message),
// the plaintext zero-padded to whole 64 KiB chunks (the server sees only the size in 64 KiB steps), each chunk
// AES-256-GCM with nonce = chunk index and the index + "last chunk" flag as associated data, so chunks can't be
// reordered, dropped or swapped between files. The SHA3-256 of the whole ciphertext also goes in the signed message.
export const FILE_CHUNK = 65536;
export const FILE_MAX = 1600 * FILE_CHUNK;                         // 100 MiB, the server's limit
function fileNonce(i) { const n = new Uint8Array(12); new DataView(n.buffer).setUint32(4, i); return n; }
const fileAad = (i, last) => utf8("dcx-chat/v1/file|" + i + "|" + (last ? 1 : 0));

export async function sealFile(bytes) {
  if (bytes.length > FILE_MAX) throw new CryptoFail("file too large");
  const raw = random(32);
  const key = await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const chunks = Math.max(1, Math.ceil(bytes.length / FILE_CHUNK));
  const out = new Uint8Array(chunks * (FILE_CHUNK + 16));
  for (let i = 0; i < chunks; i++) {
    const plain = new Uint8Array(FILE_CHUNK);
    plain.set(bytes.subarray(i * FILE_CHUNK, Math.min(bytes.length, (i + 1) * FILE_CHUNK)));
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: fileNonce(i), additionalData: fileAad(i, i === chunks - 1), tagLength: 128 }, key, plain));
    out.set(ct, i * (FILE_CHUNK + 16));
  }
  return { key: b64(raw), sealed: out, sha3: hex(sha3_256(out)), size: bytes.length };
}

export async function openFile(sealed, keyB64, size, sha3hex) {
  if (sealed.length % (FILE_CHUNK + 16) || !sealed.length) throw new CryptoFail("not an encrypted attachment");
  if (hex(sha3_256(sealed)) !== sha3hex) throw new CryptoFail("the attachment doesn't match its signed hash");
  const chunks = sealed.length / (FILE_CHUNK + 16);
  // the padding never adds a whole extra chunk: only the last chunk is partly zeros (a 0-byte file is one chunk)
  if (!(Number.isSafeInteger(size) && size >= 0 && size <= chunks * FILE_CHUNK && (chunks === 1 || size > (chunks - 1) * FILE_CHUNK)))
    throw new CryptoFail("attachment size doesn't match");
  const key = await subtle.importKey("raw", unb64(keyB64, 32), "AES-GCM", false, ["decrypt"]);
  const out = new Uint8Array(chunks * FILE_CHUNK);
  for (let i = 0; i < chunks; i++) {
    const part = sealed.subarray(i * (FILE_CHUNK + 16), (i + 1) * (FILE_CHUNK + 16));
    let plain;
    try { plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: fileNonce(i), additionalData: fileAad(i, i === chunks - 1), tagLength: 128 }, key, part)); }
    catch (e) { throw new CryptoFail("attachment decryption failed (it was changed)"); }
    out.set(plain, i * FILE_CHUNK);
  }
  return out.subarray(0, size);
}

// What a picture or video really is, from its first bytes (never from the name or the sender's label).
export function sniff(b) {
  const at = (o, ...v) => v.every((x, i) => b[o + i] === x);
  if (at(0, 0x89, 0x50, 0x4e, 0x47)) return "image/png";
  if (at(0, 0xff, 0xd8, 0xff)) return "image/jpeg";
  if (at(0, 0x47, 0x49, 0x46, 0x38)) return "image/gif";
  if (at(0, 0x52, 0x49, 0x46, 0x46) && at(8, 0x57, 0x45, 0x42, 0x50)) return "image/webp";
  if (at(4, 0x66, 0x74, 0x79, 0x70)) {
    const brand = String.fromCharCode(b[8], b[9], b[10], b[11]);
    if (brand === "avif" || brand === "avis") return "image/avif";
    if (["isom", "iso2", "mp41", "mp42", "avc1", "M4V ", "dash"].includes(brand)) return "video/mp4";
    if (brand === "qt  ") return "video/quicktime";
  }
  if (at(0, 0x1a, 0x45, 0xdf, 0xa3)) return "video/webm";
  return "application/octet-stream";
}

// ---------------------------------------------------------------------------------------------- self-test
// Known answers produced by OpenSSL 3.5 (an independent implementation, kat.js) plus round trips and tamper checks.
// The chat refuses to unlock if any of this fails, so a broken or altered crypto module is never used.
export async function selfTest() {
  const results = [];
  const check = (name, ok) => { results.push({ name, ok: !!ok }); if (!ok) throw new CryptoFail("self-test failed: " + name); };
  check("WebCrypto available", subtle && typeof subtle.importKey === "function");
  try { await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]); check("Ed25519 (WebCrypto)", true); }
  catch (e) { check("Ed25519 (WebCrypto) - this browser is too old", false); }
  try { await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]); check("X25519 (WebCrypto)", true); }
  catch (e) { check("X25519 (WebCrypto) - this browser is too old", false); }
  check("SHA3-256 known answer", hex(sha3_256(utf8("abc"))) === "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  const seed = fromHex(KAT.seed32);
  const kk = ml_kem1024.keygen(concat(seed, seed));
  check("ML-KEM-1024 key generation matches OpenSSL", hex(sha3_256(kk.publicKey)) === KAT.mlkem1024_pk_sha3);
  check("ML-KEM-1024 decapsulates OpenSSL's ciphertext", hex(ml_kem1024.decapsulate(unb64(KAT.mlkem1024_ct, SIZES.kemCt), kk.secretKey)) === KAT.mlkem1024_ss);
  const dk = ml_dsa87.keygen(seed);
  check("ML-DSA-87 key generation matches OpenSSL", hex(sha3_256(dk.publicKey)) === KAT.mldsa87_pk_sha3);
  const katSig = unb64(KAT.mldsa87_sig, SIZES.sigPqLen), katMsg = utf8(KAT.mldsa87_msg);
  check("ML-DSA-87 verifies OpenSSL's signature", ml_dsa87.verify(katSig, katMsg, dk.publicKey, { context: utf8(KAT.mldsa87_context) }));
  check("ML-DSA-87 refuses it under another context", !ml_dsa87.verify(katSig, katMsg, dk.publicKey, { context: utf8("dcx-chat/v1/other") }));
  const a = await identityFromMaster("selftest-a", random(32));
  const b = await identityFromMaster("selftest-b", random(32));
  const pubB = { kemPq: b.kemPq.pk, kemEc: b.kemEc.pub };
  const k = random(32);
  const w = await wrapKey(k, pubB, utf8("t"));
  check("hybrid key wrap round trip", sameBytes(await unwrapKey(w, b, utf8("t")), k));
  let refused = false;
  try { await unwrapKey(w, a, utf8("t")); } catch (e) { refused = e instanceof CryptoFail; }
  check("hybrid key wrap refuses the wrong recipient", refused);
  const msg = utf8("dcx");
  const s = await sign(a, "t", msg);
  const pubA = { user: a.user, sigPq: a.sigPq.pk, sigEc: a.sigEc.pub };
  check("hybrid signature verifies", await verify(pubA, "t", msg, s));
  const bad = Uint8Array.from(s); bad[10] ^= 1;
  check("hybrid signature refuses a changed ML-DSA part", !(await verify(pubA, "t", msg, bad)));
  const bad2 = Uint8Array.from(s); bad2[bad2.length - 1] ^= 1;
  check("hybrid signature refuses a changed Ed25519 part", !(await verify(pubA, "t", msg, bad2)));
  check("hybrid signature is bound to its context", !(await verify(pubA, "u", msg, s)));
  const fileBytes = random(70000);
  const sf = await sealFile(fileBytes);
  check("attachment encryption round trip", sameBytes(await openFile(sf.sealed, sf.key, sf.size, sf.sha3), fileBytes));
  const cut = sf.sealed.slice(0, FILE_CHUNK + 16);
  let truncated = false;
  try { await openFile(cut, sf.key, 1000, hex(sha3_256(cut))); } catch (e) { truncated = e instanceof CryptoFail; }
  check("attachment refuses a truncated file", truncated);
  return results;
}
