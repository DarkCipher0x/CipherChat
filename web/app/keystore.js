// CipherChat: this browser's key store (PROTOCOL.md §10). Room keys this installation has opened, kept so the server
// can delete its wrapped copies. Each key is sealed twice: by a non-extractable AES key that lives only in this
// browser's IndexedDB, and by a key derived from the person's master secret (so the profile alone opens nothing).
// Nothing here is ever uploaded or backed up; clearing the site's data or removing this browser from the device
// list wipes it.
import * as C from "./crypto.js";

const DB = "cipherchat-keystore";
const VERSION = 1;

function req(r) {
  return new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
}
function openDb() {
  return new Promise((resolve, reject) => {
    let r;
    try { r = indexedDB.open(DB, VERSION); } catch (e) { reject(e); return; }
    r.onupgradeneeded = () => {
      const db = r.result;
      if (!db.objectStoreNames.contains("installs")) db.createObjectStore("installs", { keyPath: "user" });
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys", { keyPath: "k" }).createIndex("user", "user");
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    r.onblocked = () => reject(new Error("the key store is open in another, older tab"));
  });
}
function tx(db, stores, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, mode);
    let out;
    Promise.resolve(fn(t)).then((v) => { out = v; }, reject);
    t.oncomplete = () => resolve(out);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error("key store write aborted"));
  });
}
const keyId = (user, room, epoch) => user + "|" + room + "|" + epoch;
const PREKEY = "prekey:";                              // prekey seeds (PROTOCOL.md §11): room "prekey:<id>", epoch 0

// A short, recognisable name for this browser on the device list ("Firefox on Windows").
export function browserName() {
  const ua = navigator.userAgent || "";
  const b = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  const day = new Date().toLocaleDateString("en-GB", { day: "numeric", month: "short" });
  return (b + (os ? " on " + os : "") + ", " + day).slice(0, 40);     // the date tells two of the same browser apart
}

export class Store {
  constructor(db, user, install, storeKey, device) {
    this.db = db; this.user = user; this.storeKey = storeKey; this.device = device;
    this.dev = install.dev; this.name = install.name; this.added = install.added;
    this.listedSeq = install.listedSeq || 0;
    this.seen = install.seen || {};                    // user -> {seq, ids} of device lists already shown
    this.deviceKey = install.deviceKey;
    this.isNew = !!install.isNew;
  }
  entry() {
    return { id: this.dev, name: this.name, kem_pq: C.b64(this.device.kemPq.pk), kem_ec: C.b64(this.device.kemEc.pub), added: this.added };
  }
  code() { return C.deviceCode(this.device.kemPq.pk, this.device.kemEc.pub); }
  async get(room, epoch) {
    const row = await tx(this.db, ["keys"], "readonly", (t) => req(t.objectStore("keys").get(keyId(this.user, room, epoch))));
    if (!row) return null;
    try { return await C.openStored(this.deviceKey, this.storeKey, this.user, room, epoch, row.sealed); }
    catch (e) { return null; }                         // a key sealed under an older identity: unusable, ignored
  }
  async put(room, epoch, key, at) {
    const sealed = await C.sealStored(this.deviceKey, this.storeKey, this.user, room, epoch, key);
    await tx(this.db, ["keys"], "readwrite", (t) => t.objectStore("keys").put({ k: keyId(this.user, room, epoch), user: this.user, room, epoch, at, sealed }));
  }
  // Room keys only (what history sync sends and the history window erases); prekey seeds are listed apart.
  async list() {
    const rows = await tx(this.db, ["keys"], "readonly", (t) => req(t.objectStore("keys").index("user").getAll(this.user)));
    return rows.filter((r) => !r.room.startsWith(PREKEY)).map((r) => ({ room: r.room, epoch: r.epoch, at: r.at }));
  }
  async putPrekey(id, seed, exp) { await this.put(PREKEY + id, 0, seed, exp); }
  async getPrekey(id) {
    const row = await tx(this.db, ["keys"], "readonly", (t) => req(t.objectStore("keys").get(keyId(this.user, PREKEY + id, 0))));
    if (!row) return null;
    try { return await C.openStored(this.deviceKey, this.storeKey, this.user, PREKEY + id, 0, row.sealed, 96); }
    catch (e) { return null; }
  }
  async listPrekeys() {
    const rows = await tx(this.db, ["keys"], "readonly", (t) => req(t.objectStore("keys").index("user").getAll(this.user)));
    return rows.filter((r) => r.room.startsWith(PREKEY)).map((r) => ({ id: r.room.slice(PREKEY.length), exp: r.at }));
  }
  async dropPrekeys(ids) { await this.drop(ids.map((id) => ({ room: PREKEY + id, epoch: 0 }))); }
  async drop(items) {
    if (!items.length) return;
    await tx(this.db, ["keys"], "readwrite", (t) => { for (const x of items) t.objectStore("keys").delete(keyId(this.user, x.room, x.epoch)); });
  }
  async save(fields) {
    Object.assign(this, fields);
    await tx(this.db, ["installs"], "readwrite", async (t) => {
      const s = t.objectStore("installs");
      const row = await req(s.get(this.user));
      if (row) s.put(Object.assign(row, { listedSeq: this.listedSeq, seen: this.seen, isNew: this.isNew }));
    });
  }
  // This browser stops being a device for this person: every key it held goes.
  async wipe() {
    const rows = await tx(this.db, ["keys"], "readonly", (t) => req(t.objectStore("keys").index("user").getAllKeys(this.user)));
    await tx(this.db, ["keys", "installs"], "readwrite", (t) => {
      for (const k of rows) t.objectStore("keys").delete(k);
      t.objectStore("installs").delete(this.user);
    });
  }
}

// The installation for this person in this browser: null if there is none and create is false, or if IndexedDB
// isn't available (some private windows). master is the unlocked master secret; it's only used to derive storeKey.
export async function openStore(user, master, create) {
  if (!globalThis.indexedDB) return null;
  let db;
  try { db = await openDb(); } catch (e) { return null; }
  const storeKey = await C.storeKeyFromMaster(master, user);
  let row = await tx(db, ["installs"], "readonly", (t) => req(t.objectStore("installs").get(user)));
  if (row) {
    try {
      const seed = await C.openDeviceSeed(row.deviceKey, storeKey, user, row.seed);
      const device = await C.deviceFromSeed(seed);
      seed.fill(0);
      return new Store(db, user, row, storeKey, device);
    } catch (e) {
      // Sealed under an earlier identity (a reset) or damaged: this installation and its keys can't be opened any more.
      const old = await tx(db, ["keys"], "readonly", (t) => req(t.objectStore("keys").index("user").getAllKeys(user)));
      await tx(db, ["installs", "keys"], "readwrite", (t) => {
        t.objectStore("installs").delete(user);
        for (const k of old) t.objectStore("keys").delete(k);
      });
      row = null;
    }
  }
  if (!create) return null;
  const deviceKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const seed = C.newDeviceSeed();
  const device = await C.deviceFromSeed(seed);
  const install = { user, dev: C.newStoreDeviceId(), name: browserName(), added: Date.now(), deviceKey,
                    seed: await C.sealDeviceSeed(deviceKey, storeKey, user, seed), listedSeq: 0, seen: {}, isNew: true };
  seed.fill(0);
  await tx(db, ["installs"], "readwrite", (t) => t.objectStore("installs").put(install));
  return new Store(db, user, install, storeKey, device);
}

// True if this browser already keeps keys for this person (asked before unlocking, so the question isn't repeated).
export async function hasInstall(user) {
  if (!globalThis.indexedDB) return false;
  try {
    const db = await openDb();
    return !!(await tx(db, ["installs"], "readonly", (t) => req(t.objectStore("installs").get(user))));
  } catch (e) { return false; }
}
