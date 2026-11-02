// CipherChat history tests (test page only, never shipped): device lists, the key store's double seal, history-sync
// packages and the header check for keys a device already holds (PROTOCOL.md §10). Makes browser-history.json for
// the other clients and opens theirs (fixtures/windows-history.json, fixtures/phone-history.json) when present.
import * as C from "../app/crypto.js";
import { KeyHistory } from "../app/history.js";

const out = document.getElementById("out");
const results = (window.__results = { done: false, pass: 0, fail: 0, lines: [] });
function log(ok, name, detail) {
  results[ok ? "pass" : "fail"]++;
  const line = (ok ? "PASS " : "FAIL ") + name + (detail ? "  (" + detail + ")" : "");
  results.lines.push(line);
  out.textContent += line + "\n";
}
async function refused(fn) { try { await fn(); return false; } catch (e) { return true; } }
const rawAes = (b) => crypto.subtle.importKey("raw", b, "AES-GCM", false, ["encrypt", "decrypt"]);

// Everything a fixture holds, made from fresh secrets.
async function makeFixture(by) {
  const user = "alice", room = "0123456789abcdef";
  const master = C.random(32);
  const id = await C.identityFromMaster(user, master);
  const { bundle, fp } = await C.publishIdentity(id, Date.now());
  const seedFrom = C.newDeviceSeed(), seedTo = C.newDeviceSeed();
  const devFrom = await C.deviceFromSeed(seedFrom), devTo = await C.deviceFromSeed(seedTo);
  const from = C.newStoreDeviceId(), to = C.newStoreDeviceId();
  const entry = (i, d, name) => ({ id: i, name, kem_pq: C.b64(d.kemPq.pk), kem_ec: C.b64(d.kemEc.pub), added: 1790000000000 });
  const devices = await C.publishDevices(id, fp, 1, [entry(from, devFrom, "Old laptop"), entry(to, devTo, "New phone")], Date.now());
  const pub = await C.openIdentity(Object.assign({ fp }, bundle), user);
  const { pkg, key } = await C.buildEpoch(id, fp, room, 1, [{ u: user, fp, pub }], "");
  const blob = await C.sealKeySync(id, from, to, { kemPq: devTo.kemPq.pk, kemEc: devTo.kemEc.pub }, [{ room, epoch: 1, key }], Date.now());
  const tampered = C.unb64(blob); tampered[tampered.length - 20] ^= 1;
  const deviceKey = C.random(32);
  const sealed = await C.sealStored(await rawAes(deviceKey), await C.storeKeyFromMaster(master, user), user, room, 1, key);
  // protocol 2: a prekey for each device, and a per-device room key (epoch 2) wrapped to them
  const v2 = {};
  const now = Date.now();
  const preSeedFrom = C.newDeviceSeed(), preSeedTo = C.newDeviceSeed();
  const preFrom = await C.deviceFromSeed(preSeedFrom), preTo = await C.deviceFromSeed(preSeedTo);
  const idFrom = C.newPrekeyId(), idTo = C.newPrekeyId();
  v2.prekey_from = await C.publishPrekey(id, fp, from, idFrom, preFrom, now);
  v2.prekey_to = await C.publishPrekey(id, fp, to, idTo, preTo, now);
  v2.prekey_seed_to = C.b64(preSeedTo);
  const opened = [await C.openPrekey(v2.prekey_from, pub, [from, to], now), await C.openPrekey(v2.prekey_to, pub, [from, to], now)];
  const e2 = await C.buildEpochV2(id, fp, room, 2, [{ u: user, fp, dev: to, prekey: opened[1] }, { u: user, fp, dev: from, prekey: opened[0] }], "");
  v2.epoch_item = { epoch: 2, from: user, body: { v: 2, h: e2.pkg.h, s: e2.pkg.s, w: e2.pkg.w[user + "|" + to] } };
  v2.w_from = e2.pkg.w[user + "|" + from];
  const bad = C.unb64(v2.epoch_item.body.w); bad[bad.length - 5] ^= 1;
  v2.w_tampered = C.b64(bad);
  v2.room_key = C.hex(e2.key);
  return { v: 1, made_by: by, user, master: C.hex(master), fp, bundle, devices, from, to, v2,
           device_seed_to: C.b64(seedTo), code_to: C.deviceCode(devTo.kemPq.pk, devTo.kemEc.pub),
           room, epoch_item: { epoch: 1, from: user, body: { h: pkg.h, s: pkg.s } }, room_key: C.hex(key),
           sync_blob: blob, sync_tampered: C.b64(tampered),
           store: { device_key: C.b64(deviceKey), sealed: C.b64(sealed), room, epoch: 1 } };
}

// What every client checks on a fixture any client made.
async function openFixture(f, name) {
  const master = C.fromHex(f.master);
  const id = await C.identityFromMaster(f.user, master);
  const me = await C.publishIdentity(id, JSON.parse(new TextDecoder().decode(C.unb64(f.bundle.b))).at);
  log(me.fp === f.fp, name + ": the identity rebuilds from its master to the same fingerprint");
  const pub = await C.openIdentity(Object.assign({ fp: f.fp }, f.bundle), f.user);
  const list = await C.openDevices(f.devices, pub);
  log(list.seq === 1 && list.devices.length === 2, name + ": its device list verifies (ML-DSA-87 + Ed25519)");
  const to = await C.deviceFromSeed(C.unb64(f.device_seed_to, 96));
  const listed = list.devices.find((d) => d.id === f.to);
  log(listed && listed.kem_pq === C.b64(to.kemPq.pk) && listed.kem_ec === C.b64(to.kemEc.pub), name + ": the device key rebuilds from its seed to the listed public key");
  log(C.deviceCode(to.kemPq.pk, to.kemEc.pub) === f.code_to, name + ": the device code matches (" + f.code_to + ")");
  const keys = await C.openKeySync(to, pub, f.from, f.to, f.sync_blob);
  log(keys.length === 1 && keys[0].room === f.room && C.hex(keys[0].key) === f.room_key, name + ": the history package opens to the room key");
  const item = Object.assign({}, f.epoch_item, { body: Object.assign({ w: null }, f.epoch_item.body) });
  const ok = await C.checkEpoch(id, f.fp, f.room, item, pub, keys[0].key).then(() => true, () => false);
  log(ok, name + ": the key passes the signed header's commitment without its wrap");
  log(await refused(() => C.checkEpoch(id, f.fp, f.room, item, pub, C.random(32))), name + ": a different key is refused by the commitment");
  log(await refused(() => C.openKeySync(to, pub, f.from, f.to, f.sync_tampered)), name + ": a changed package is refused");
  log(await refused(() => C.openKeySync(to, pub, f.to, f.from, f.sync_blob)), name + ": a package can't be replayed between other devices");
  const other = await C.deviceFromSeed(C.newDeviceSeed());
  log(await refused(() => C.openKeySync(other, pub, f.from, f.to, f.sync_blob)), name + ": another device can't open it");
  const sk = await C.storeKeyFromMaster(master, f.user);
  const dk = await rawAes(C.unb64(f.store.device_key, 32));
  const stored = await C.openStored(dk, sk, f.user, f.store.room, f.store.epoch, C.unb64(f.store.sealed));
  log(C.hex(stored) === f.room_key, name + ": the key store's double seal opens with the device key and the master");
  log(await refused(() => C.openStored(dk, sk, f.user, f.store.room, 2, C.unb64(f.store.sealed))), name + ": a stored key can't be moved to another epoch");
  const wrongMaster = await C.storeKeyFromMaster(C.random(32), f.user);
  log(await refused(() => C.openStored(dk, wrongMaster, f.user, f.store.room, f.store.epoch, C.unb64(f.store.sealed))), name + ": the device key alone (no passphrase) opens nothing");
  if (!f.v2) { out.textContent += "skip " + name + " protocol 2 (made before it)\n"; return; }
  // protocol 2: prekeys and a per-device room key
  const v = f.v2, at = (e) => JSON.parse(new TextDecoder().decode(C.unb64(e.b))).at;
  const ids = list.devices.map((d) => d.id);
  const pTo = await C.openPrekey(v.prekey_to, pub, ids, at(v.prekey_to));
  const pre = await C.deviceFromSeed(C.unb64(v.prekey_seed_to, 96));
  log(pTo.dev === f.to && C.b64(pTo.kemPq) === C.b64(pre.kemPq.pk) && C.b64(pTo.kemEc) === C.b64(pre.kemEc.pub), name + ": v2 prekey verifies and its seed rebuilds to it");
  log(await refused(() => C.openPrekey(v.prekey_to, pub, [f.from], at(v.prekey_to))), name + ": v2 prekey of a device that isn't listed is refused");
  log(await refused(() => C.openPrekey(v.prekey_to, pub, ids, at(v.prekey_to) + 7 * 86400 * 1000)), name + ": v2 expired prekey is refused");
  const mine = async (pid) => (pid === pTo.id ? pre : null);
  const e2 = await C.openEpochV2(id, f.fp, f.to, f.room, v.epoch_item, pub, mine);
  log(C.hex(e2.key) === v.room_key && e2.header.v === 2, name + ": v2 per-device room key opens with the device's prekey");
  log(await C.checkEpoch(id, f.fp, f.room, Object.assign({}, v.epoch_item, { body: Object.assign({}, v.epoch_item.body, { w: null }) }), pub, e2.key).then(() => true, () => false),
      name + ": v2 key passes the signed header's commitment without its wrap");
  const tamper = Object.assign({}, v.epoch_item, { body: Object.assign({}, v.epoch_item.body, { w: v.w_tampered }) });
  log(await refused(() => C.openEpochV2(id, f.fp, f.to, f.room, tamper, pub, mine)), name + ": v2 changed wrap is refused");
  const asFrom = Object.assign({}, v.epoch_item, { body: Object.assign({}, v.epoch_item.body, { w: v.w_from }) });
  log(await refused(() => C.openEpochV2(id, f.fp, f.from, f.room, asFrom, pub, mine)), name + ": v2 another device's wrap doesn't open with this device's prekey");
  log(await refused(() => C.openEpochV2(id, f.fp, f.to, f.room, v.epoch_item, pub, async () => null)), name + ": v2 without the prekey (erased) nothing opens");
  log(await refused(() => C.openEpoch(id, f.fp, f.room, v.epoch_item, pub)), name + ": v2 header isn't accepted as a v1 room key");
}

async function main() {
  try {
    const f = await makeFixture("browser");
    window.__fixture = f;
    await openFixture(f, "browser-made");
    // the list itself: rollback and identity checks
    const id = await C.identityFromMaster(f.user, C.fromHex(f.master));
    const pub = await C.openIdentity(Object.assign({ fp: f.fp }, f.bundle), f.user);
    const evil = await C.identityFromMaster("alice", C.random(32));
    const forged = await C.publishDevices(evil, f.fp, 2, [], Date.now());
    log(await refused(() => C.openDevices(forged, pub)), "a device list signed by another key is refused");
    const wrongFp = await C.publishDevices(id, "0".repeat(64), 2, [], Date.now());
    log(await refused(() => C.openDevices(wrongFp, pub)), "a device list for another fingerprint is refused");
    // a room key header this device can't open still gives the hash the next key names as "prev", once its signature checks out
    const e1 = await C.buildEpoch(id, f.fp, f.room, 1, [{ u: f.user, fp: f.fp, pub }], "");
    const it1 = { epoch: 1, from: f.user, body: e1.pkg };
    const prev = await C.headerHashOf(f.room, it1, pub);
    log(prev === C.headerHash(C.unb64(e1.pkg.h)), "an unopened header's hash is the header hash");
    const e2 = await C.buildEpoch(id, f.fp, f.room, 2, [{ u: f.user, fp: f.fp, pub }], prev);
    const o2 = await C.openEpoch(id, f.fp, f.room, { epoch: 2, from: f.user, body: { h: e2.pkg.h, s: e2.pkg.s, w: e2.pkg.w[f.user] } }, pub);
    log(o2.header.prev === prev, "the next key names it as prev");
    log(await refused(() => C.headerHashOf("fedcba9876543210", it1, pub)), "an unopened header replayed into another room is refused");
    log(await refused(() => C.headerHashOf(f.room, Object.assign({}, it1, { epoch: 2 }), pub)), "an unopened header as another epoch is refused");
    log(await refused(() => C.headerHashOf(f.room, Object.assign({}, it1, { from: "mallory" }), pub)), "an unopened header from someone else is refused");
    const badSig = C.unb64(e1.pkg.s); badSig[10] ^= 1;
    log(await refused(() => C.headerHashOf(f.room, { epoch: 1, from: f.user, body: { h: e1.pkg.h, s: C.b64(badSig) } }, pub)), "an unopened header with a changed signature is refused");
    for (const name of ["windows-history.json", "phone-history.json"]) {
      const r = await fetch("fixtures/" + name, { cache: "no-store" }).catch(() => null);
      if (r && r.ok) await openFixture(await r.json(), name);
      else out.textContent += "skip " + name + " (not there yet)\n";
    }
    const now = Date.now() / 1000, day = 86400;
    const listed = [{ at: now - 30 * day, body: { w: "x" } }, { at: now - 9 * day, body: { w: "x" } },
                    { at: now - 7.5 * day, body: { w: "x" } }, { at: now - 30 * day, body: { w: null } }, { at: now, body: { w: "x" } }];
    log(KeyHistory.leftover(listed) === 2, "wraps kept past the grace period (plus a day) are counted, nothing else");
  } catch (e) { log(false, "unexpected error", e.message); }
  results.done = true;
  out.textContent += "\n" + results.pass + " passed, " + results.fail + " failed\n";
}
main();
