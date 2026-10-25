// CipherChat by DarkCipher Systems: the cryptography of calls (docs/CALLS.md). Shared by the web portal, the Windows
// app (WebView2) and the Android app (WebView); only the chat's own primitives from crypto.js are used.
//
//   signals      every call signal is a canonical JSON header signed ML-DSA-87 + Ed25519 ("dcx-chat/v1/call-signal")
//                and accepted only from a TRUSTED identity, fresh (2 minutes) and never twice (replay set)
//   sender keys  each participant makes its own random 256-bit media key per epoch and wraps it to every other
//                participant with the hybrid ML-KEM-1024 + X25519 wrap ("dcx-chat/v1/call-key|..."); a new epoch
//                whenever someone joins or leaves, so nobody hears what was said before they came or after they left
//   frames       callworker.js derives an AES-256-GCM key per sender, epoch and stream from the sender key
//                (HKDF-SHA-512) and encrypts every encoded audio and video frame with it
//   call words   four words from the call id and every participant's identity fingerprint, read aloud to compare
import * as C from "./crypto.js";
import { sha3_256 } from "./vendor/hashes/sha3.js";

export const SIGNAL_LABEL = "dcx-chat/v1/call-signal";
const SIGNAL_MAX = 48 * 1024;
const FRESH_MS = 120000;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const DEV_RE = /^[A-Za-z0-9_-]{8,22}$/;
export const KINDS = ["ring", "accept", "decline", "busy", "offer", "answer", "ice", "key", "leave", "end", "state"];

const b64url = (b) => C.b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const newCallId = () => b64url(C.random(16));          // 22 characters
export const newDeviceId = () => b64url(C.random(12));        // 16 characters: this tab / app instance

// ---------------------------------------------------------------------------------------------- signals
export async function sealSignal(me, myFp, fields) {
  const hdr = Object.assign({ v: 1, t: "call", from: me.user, from_fp: myFp, at: Date.now(), n: b64url(C.random(9)) }, fields);
  const raw = C.canonBytes(hdr);
  if (raw.length > SIGNAL_MAX) throw new C.CryptoFail("call signal too large");
  return { h: C.b64(raw), s: C.b64(await C.sign(me, SIGNAL_LABEL, raw)) };
}

// item = one entry of poll().signals. trusted(user) -> {pub, fp} or null. seen: a Set the caller keeps (replays).
export async function openSignal(item, trusted, seen) {
  const { raw, obj } = C.parseSigned(item.sig.h, SIGNAL_MAX);
  if (obj.t !== "call" || obj.from !== item.from || obj.room !== item.room || obj.kind !== item.kind || obj.call !== item.call)
    throw new C.CryptoFail("call signal doesn't match its envelope");
  if (!KINDS.includes(obj.kind) || !ID_RE.test(obj.call) || !DEV_RE.test(obj.dev || "") || !Array.isArray(obj.to))
    throw new C.CryptoFail("malformed call signal");
  if (Math.abs(Date.now() - obj.at) > FRESH_MS) throw new C.CryptoFail("call signal is stale");
  const who = trusted(obj.from);
  if (!who || who.fp !== obj.from_fp) throw new C.CryptoFail("call signal from an identity you don't trust");
  if (!(await C.verify(who.pub, SIGNAL_LABEL, raw, C.unb64(item.sig.s)))) throw new C.CryptoFail("call signal signature is invalid");
  const tag = obj.call + "|" + obj.dev + "|" + obj.n;
  if (seen.has(tag)) throw new C.CryptoFail("replayed call signal");
  seen.add(tag);
  if (seen.size > 5000) seen.delete(seen.values().next().value);
  return obj;
}

// ---------------------------------------------------------------------------------------------- sender keys
const keyAad = (call, from, dev, epoch, to, toFp) => C.utf8(["dcx-chat/v1/call-key", call, from, dev, epoch, to, toFp].join("|"));

// recipients: [{u, fp, pub}] -> {epoch, keys: {user: b64 wrapped}} for a "key" signal
export async function wrapSenderKey(key32, call, me, dev, epoch, recipients) {
  const keys = {};
  for (const r of recipients) keys[r.u] = C.b64(await C.wrapKey(key32, r.pub, keyAad(call, me.user, dev, epoch, r.u, r.fp)));
  return { epoch, keys };
}

export async function unwrapSenderKey(sig, myId, myFp) {
  const w = sig.keys && sig.keys[myId.user];
  if (typeof w !== "string" || !Number.isInteger(sig.epoch) || sig.epoch < 0) throw new C.CryptoFail("no call key for you in this signal");
  return C.unwrapKey(C.unb64(w), myId, keyAad(sig.call, sig.from, sig.dev, sig.epoch, myId.user, myFp));
}

// ---------------------------------------------------------------------------------------------- call words
// 256 short, distinct, easy-to-say words: one per byte (like the PGP word list, but plain English nouns)
const WORDS = ("acorn agent alpha amber anchor angel apple arrow atlas autumn badge baker bamboo banjo barrel basin beacon " +
  "beaver bishop blanket blossom bonus border bottle bounty bracket bridge bronze bubble bucket buffalo butter cabin cactus " +
  "camel candle canyon captain carbon carpet castle cedar cello chalk channel cherry chess chimney cider cinema circus citrus " +
  "clover cobalt cocoa comet compass copper coral cotton coyote crater crayon cricket crystal cupcake cyclone dancer delta " +
  "denim desert diamond dingo dolphin domino dragon dream drum eagle easel echo eclipse ember emerald engine falcon feather fennel " +
  "ferry fiddle finch flame flint forest fossil fountain fox galaxy garden garlic gazelle gecko geyser ginger glacier globe goblet " +
  "granite gravel guitar hammer harbor harvest hazel helmet hickory honey horizon hornet iceberg igloo indigo island ivory " +
  "jacket jaguar jasmine jelly jewel jungle kayak kernel kettle kiwi koala ladder lagoon lantern laser lemon lentil leopard lilac " +
  "linen lobster locket lotus magnet mango maple marble meadow melon meteor mint mirror mitten monsoon mosaic muffin nectar needle " +
  "nickel nugget oasis ocean olive onyx opal orbit orchid otter oyster paddle palace panda paper parrot pebble pepper piano " +
  "pilot pine planet plaza pocket pollen pony poppy prism pumpkin puzzle quartz quill rabbit radar raven reef ribbon river " +
  "robin rocket ruby saddle saffron salmon satin scarlet scooter shadow shell signal silver sketch sparrow spice spiral sprout " +
  "squirrel star stone sugar summit sunset swan tango teapot temple thistle thunder tiger timber toffee topaz torch tower tulip " +
  "tundra turtle umbrella valley velvet violet volcano wagon walnut walrus willow window winter wizard yacht yarrow zebra zephyr zinc").split(" ");

export function callWords(call, participants) {
  const lines = participants.map((p) => p.u + ":" + p.fp).sort();
  const h = C.hex(sha3_256(C.utf8(["dcx-chat/v1/call-words", call, ...lines].join("|")))).slice(0, 8);
  return [0, 2, 4, 6].map((i) => WORDS[parseInt(h.slice(i, i + 2), 16)]);
}

if (WORDS.length !== 256 || new Set(WORDS).size !== 256) throw new Error("call word list must be 256 distinct words");

// ---------------------------------------------------------------------------------------------- the browser's host
// call.js's crypto functions for the web portal: the identity is this tab's (unlocked by the gate), dev this tab's
// device id. trusted(user) -> {pub, fp} | null (trust.js decides).
export function webHost(me, myFp, dev, trusted) {
  const people = (users) => users.map((u) => { const t = trusted(u); if (!t) throw new C.CryptoFail(u + " isn't verified"); return { u, fp: t.fp, pub: t.pub }; });
  return {
    seal: (fields) => sealSignal(me, myFp, fields),
    open: (item, seen) => openSignal(item, trusted, seen),
    wrapKey: (key32, call, epoch, users) => wrapSenderKey(key32, call, me, dev, epoch, people(users)),
    unwrapKey: (sig) => unwrapSenderKey(sig, me, myFp),
    words: (call, users) => callWords(call, users.map((u) => (u === me.user ? { u, fp: myFp } : { u, fp: trusted(u).fp }))),
  };
}
