// CipherChat: devices, the key store and history in the web chat (PROTOCOL.md §10, PREKEYS-DESIGN.md phase 1).
//   - this browser joins the person's signed device list, keeps the room keys it opens, and acknowledges them, so the
//     server can delete its wrapped copies;
//   - a new browser asks the person's other devices for older keys; they ask the person first and show a device code;
//   - device lists are checked against the owner's trust like everything else, and changes are shown;
//   - each room's history window is applied to the keys kept here.
// The host object (app.js) gives: api, st() (server state), store, me {id, fp, user}, trusted(user), room(id),
// say {sys, warn, ok, fail}, confirm(title, lines, buttons) -> value, refresh().
import * as C from "./crypto.js";

const MAX_DEVICES = 16;
const PACK_KEYS = 1500;                      // keys per history package (stays under the server's 192 KiB per blob)
const PREKEY_EVERY_MS = 86400 * 1000;        // a new prekey each day (each lives 7 days)
const PREKEY_CHECK_MS = 3600 * 1000;         // how often a long-open tab looks again
const V2_MAX_DEVICES = 64;                   // per-device room keys for at most this many devices (the server's limit)
export const GRACE_DAYS = 7;                 // the server deletes a wrap no device acknowledged after this long
export const LEFTOVER_WARNING = (n) => "The server still holds " + n + (n === 1 ? " copy" : " copies") +
  " of this room's keys for you that are more than " + GRACE_DAYS + " days old; it should have deleted them. That " +
  "happens while an older CipherChat app of yours is still signed in or paired: update or remove it (/devices). If " +
  "none is, the server isn't deleting them as it should.";

export class KeyHistory {
  constructor(host) {
    this.h = host;
    this.pending = new Map();                // room -> Set(epoch) to acknowledge
    this.asked = new Set();                  // sync requests already put to the person this session
    this.busy = false;
    this.ackTimer = null;
    this.preCache = new Map();               // prekey id -> its key pair, while unlocked
    this.preChecked = 0;
  }
  get store() { return this.h.store; }
  myPub() {
    const id = this.h.me.id;
    return { user: id.user, fp: this.h.me.fp, sigPq: id.sigPq.pk, sigEc: id.sigEc.pub };
  }
  entryOf(user) { return (this.h.st().directory.find((d) => d.user === user) || {}).devices || null; }

  async myList() {
    const e = this.entryOf(this.h.me.user);
    if (!e) return null;
    try { return await C.openDevices(e, this.myPub()); }
    catch (err) { this.h.say.fail("Your device list on the server doesn't verify (" + err.message + "). It won't be used or changed until that's fixed."); throw err; }
  }

  // Joins this browser to the device list (once), says hello, and asks other devices for history if it's new here.
  async enroll() {
    const S = this.store;
    if (!S) return;
    let others = [];
    for (let attempt = 0; attempt < 3; attempt++) {
      const list = await this.myList();
      if (list && list.devices.some((d) => d.id === S.dev)) { others = []; break; }
      if (list && S.listedSeq && list.seq > S.listedSeq) {
        await this.removed();                // another of my devices removed this browser: everything it kept goes
        return;
      }
      others = list ? list.devices.slice() : [];
      if (others.length >= MAX_DEVICES) {
        const seen = this.h.st().me.device_seen || {};
        others.sort((a, b) => (seen[a.id] || 0) - (seen[b.id] || 0));
        const gone = others.shift();
        this.h.say.warn("Your device list was full, so the least recently used device (" + gone.name + ") was removed from it.");
      }
      const seq = list ? list.seq + 1 : 1;
      const signed = await C.publishDevices(this.h.me.id, this.h.me.fp, seq, others.concat([S.entry()]), Date.now());
      try {
        await this.h.api("keydevices", { list: signed, dev: S.dev });
        await S.save({ listedSeq: seq });
        await this.h.refresh();
        break;
      } catch (e) {
        if (!(e.data && e.data.stale)) throw e;
        await this.h.refresh();
      }
    }
    await this.h.api("store/hello", { dev: S.dev });
    if (S.isNew) {
      if (others.length) {
        await this.h.api("sync/request", { dev: S.dev });
        this.h.say.sys("Asked your other devices for this browser's history. Approve it on one of them, and check it shows this code: " + S.code());
      }
      await S.save({ isNew: false });
    }
  }

  // Every state change: device lists (shown when they change), my own membership, sync work, the history window.
  async onState() {
    if (this.busy) return;
    this.busy = true;
    try {
      await this.checkLists();
      if (this.store && (this.h.st().me.sync_waiting || 0) > 0) await this.syncWork();
      if (this.store && this.preChecked && Date.now() - this.preChecked > PREKEY_CHECK_MS) await this.prekeys();
    } catch (e) { this.h.say.fail("Device and history check failed: " + e.message); }
    finally { this.busy = false; }
  }

  async checkLists() {
    const S = this.store;
    const seen = S ? S.seen : {};
    let changed = false;
    for (const d of this.h.st().directory) {
      if (!d.devices) continue;
      const mine = d.user === this.h.me.user;
      const p = mine ? { pub: this.myPub() } : this.h.trusted(d.user);
      if (!p) continue;
      let list;
      try { list = await C.openDevices(d.devices, p.pub); }
      catch (e) { this.h.say.warn(d.user + "'s device list doesn't verify (" + e.message + "): ignored."); continue; }
      const before = seen[d.user];
      const ids = list.devices.map((x) => x.id);
      if (before && list.seq < before.seq) { this.h.say.warn(d.user + "'s device list went back to an older version (" + list.seq + " after " + before.seq + "). The server may be replaying it."); continue; }
      if (before && before.seq !== list.seq) {
        const added = list.devices.filter((x) => !before.ids.includes(x.id)).map((x) => x.name);
        const removed = before.ids.length - ids.filter((x) => before.ids.includes(x)).length;
        const who = mine ? "A device was added to your account" : d.user + " added a device";
        if (added.length) (mine ? this.h.say.warn : this.h.say.sys)(who + ": " + added.join(", ") + (mine ? ". If that wasn't you, reset your identity (/reset-identity)." : "."));
        if (removed) this.h.say.sys((mine ? "You" : d.user) + " removed " + removed + " device" + (removed > 1 ? "s" : "") + ".");
      }
      if (!before || before.seq !== list.seq) { seen[d.user] = { seq: list.seq, ids }; changed = true; }
      if (mine && S && S.listedSeq && list.seq > S.listedSeq && !ids.includes(S.dev)) {
        await this.removed();
        return;
      }
    }
    if (S && changed) await S.save({ seen });
  }

  // ---------------------------------------------------------------- keys: kept, acknowledged, windowed
  // Wraps for me the server still has past the grace period (PREKEYS-DESIGN §4.2), from an epochs?all=1 listing.
  // One day of slack covers the server's sweep interval and clock drift.
  static leftover(items) {
    const cutoff = Date.now() / 1000 - (GRACE_DAYS + 1) * 86400;
    return items.filter((it) => it.body && it.body.w && it.at < cutoff).length;
  }
  inWindow(info, epoch, at) {
    if (!info) return false;
    if (epoch === info.epoch || !info.history_days) return true;
    return at >= Date.now() - info.history_days * 86400 * 1000;
  }
  async kept(room, epoch) { return this.store ? this.store.get(room, epoch) : null; }
  async keep(room, epoch, key, at) {
    if (!this.store) return;
    await this.store.put(room, epoch, key, at);
    if (!this.pending.has(room)) this.pending.set(room, new Set());
    this.pending.get(room).add(epoch);
    clearTimeout(this.ackTimer);
    this.ackTimer = setTimeout(() => this.flushAcks().catch(() => {}), 300);
  }
  async flushAcks() {
    if (!this.store) return;
    const work = [...this.pending.entries()];
    this.pending.clear();
    for (const [room, set] of work) {
      const epochs = [...set];
      for (let i = 0; i < epochs.length; i += 1000) {
        try { await this.h.api("rooms/" + room + "/ack", { dev: this.store.dev, epochs: epochs.slice(i, i + 1000) }); }
        catch (e) { if (e.status !== 404) for (const x of epochs.slice(i, i + 1000)) this.pendingAdd(room, x); }
      }
    }
  }
  pendingAdd(room, epoch) { if (!this.pending.has(room)) this.pending.set(room, new Set()); this.pending.get(room).add(epoch); }

  // Keys past a room's history window (never the current one) and keys of rooms I'm no longer in are erased here.
  async applyWindow() {
    if (!this.store) return [];
    const rooms = new Map(this.h.st().rooms.map((r) => [r.id, r]));
    const gone = (await this.store.list()).filter((x) => !this.inWindow(rooms.get(x.room), x.epoch, x.at));
    await this.store.drop(gone);
    return gone;
  }

  // Opens every room's wraps once, so this device holds (and acknowledges) every key it can: the server can then
  // delete them. Run in the background after unlocking.
  async importAll(openRoomKeys) {
    if (!this.store) return;
    for (const r of this.h.st().rooms) {
      try { await openRoomKeys(r.id); } catch (e) { /* a room that fails here is retried when it's opened */ }
    }
    await this.flushAcks();
  }

  // ---------------------------------------------------------------- prekeys (protocol 2, PROTOCOL.md §11)
  async prekeyOf(id) {
    if (!this.store) return null;
    if (this.preCache.has(id)) return this.preCache.get(id);
    const seed = await this.store.getPrekey(id);
    if (!seed) return null;
    const pair = await C.deviceFromSeed(seed);
    seed.fill(0);
    this.preCache.set(id, pair);
    return pair;
  }

  // Publishes a new prekey when the newest is a day old (or the server lost it), and erases expired ones, but only
  // after opening and keeping every room key still wrapped to them (host.openAll). After unlocking, then hourly.
  // With erase false it only publishes (at unlock, before the import has run).
  async prekeys(erase = true) {
    const S = this.store;
    if (!S) return;
    this.preChecked = Date.now();
    const now = Date.now();
    const mine = await S.listPrekeys();
    const expired = mine.filter((p) => p.exp <= now);
    if (erase && expired.length) {
      if (this.h.openAll) await this.h.openAll();
      await S.dropPrekeys(expired.map((p) => p.id));
      expired.forEach((p) => this.preCache.delete(p.id));
    }
    const live = mine.filter((p) => p.exp > now).sort((a, b) => b.exp - a.exp);
    const entry = this.h.st().directory.find((d) => d.user === this.h.me.user) || {};
    const onServer = new Set((entry.prekeys || []).map((e) => { try { return C.parseSigned(e.b, 4096, [2]).obj.id; } catch (err) { return null; } }));
    let pub = null;
    if (!live.length || now - (live[0].exp - C.PREKEY_LIFE_MS) >= PREKEY_EVERY_MS) {
      const id = C.newPrekeyId(), seed = C.newDeviceSeed();
      await S.putPrekey(id, seed, now + C.PREKEY_LIFE_MS);
      const pair = await C.deviceFromSeed(seed);
      seed.fill(0);
      this.preCache.set(id, pair);
      pub = { id, pair, at: now };
    } else if (!onServer.has(live[0].id)) {
      pub = { id: live[0].id, pair: await this.prekeyOf(live[0].id), at: live[0].exp - C.PREKEY_LIFE_MS };
    }
    if (pub && pub.pair) {
      const signed = await C.publishPrekey(this.h.me.id, this.h.me.fp, S.dev, pub.id, pub.pair, pub.at);
      await this.h.api("keydevices/prekey", { dev: S.dev, prekey: signed });
      await this.h.refresh();
    }
  }

  // True unless a verified device list of this person (seen here) leaves the device out.
  deviceListed(user, dev) {
    const seen = this.store && this.store.seen[user];
    return !seen || seen.ids.includes(dev);
  }

  // The lines of a per-device room key for these people ({lines}), or {why} it can't be made (PROTOCOL.md §11): each
  // person's device list and every listed device's newest prekey must verify against their trusted identity.
  async v2Lines(users) {
    if (!this.store) return { why: "this browser keeps no room keys" };
    const lines = [];
    for (const u of users) {
      const d = this.h.st().directory.find((x) => x.user === u);
      const p = u === this.h.me.user ? { pub: this.myPub(), fp: this.h.me.fp } : this.h.trusted(u);
      if (!d || !p) return { why: u + " isn't verified" };
      if (!d.devices) return { why: u + " has no device list yet" };
      if (!d.v2) return { why: u + " has an older app signed in" };
      let list;
      try { list = await C.openDevices(d.devices, p.pub); } catch (e) { return { why: u + "'s device list doesn't verify" }; }
      const ids = list.devices.map((x) => x.id);
      const best = new Map();
      for (const e of d.prekeys || []) {
        let pk;
        try { pk = await C.openPrekey(e, p.pub, ids); } catch (err) { continue; }
        const cur = best.get(pk.dev);
        if (!cur || pk.at > cur.at) best.set(pk.dev, pk);
      }
      for (const x of list.devices) {
        const pk = best.get(x.id);
        if (!pk) return { why: u + "'s device \"" + x.name + "\" has no fresh prekey" };
        lines.push({ u, fp: p.fp, dev: x.id, prekey: pk });
      }
    }
    if (lines.length > V2_MAX_DEVICES) return { why: "the room has more than " + V2_MAX_DEVICES + " devices" };
    return { lines };
  }

  // ---------------------------------------------------------------- history sync
  async syncWork() {
    const S = this.store;
    const st = await this.h.api("sync?dev=" + S.dev);
    const list = await this.myList();
    const byId = new Map((list ? list.devices : []).map((d) => [d.id, d]));
    for (const p of st.packages) await this.receive(p, byId.get(p.from));
    for (const r of st.requests) {
      if (this.asked.has(r.id)) continue;
      this.asked.add(r.id);
      const d = byId.get(r.dev);
      if (!d) continue;
      const code = C.deviceCode(C.unb64(d.kem_pq), C.unb64(d.kem_ec));
      const v = await this.h.confirm("Send history to a new device?", [
        "\"" + d.name + "\" (added " + new Date(d.added).toLocaleString() + ") is asking for the room keys this browser holds, so it can read older messages.",
        "Approve only if it's your own device and it shows this code: " + code,
        "Rooms whose admins turned history sync off aren't included, and nothing older than each room's history window."],
        [{ label: "Decline", value: "no" }, { label: "Not now" }, { label: "Approve", cls: "primary", value: "yes" }]);
      if (v === "yes") await this.send(d);
      else if (v === "no") await this.h.api("sync/decline", { id: r.id }).catch(() => {});
    }
  }

  async send(d) {
    const S = this.store;
    const rooms = new Map(this.h.st().rooms.map((r) => [r.id, r]));
    const keys = [];
    for (const x of await S.list()) {
      const info = rooms.get(x.room);
      if (!info || !info.history_sync || !this.inWindow(info, x.epoch, x.at)) continue;
      const key = await S.get(x.room, x.epoch);
      if (key) keys.push({ room: x.room, epoch: x.epoch, key });
    }
    keys.sort((a, b) => (a.room < b.room ? -1 : a.room > b.room ? 1 : a.epoch - b.epoch));
    const target = { kemPq: C.unb64(d.kem_pq, C.SIZES.kemPq), kemEc: C.unb64(d.kem_ec, C.SIZES.kemEc) };
    const parts = [];
    for (let i = 0; i < keys.length; i += PACK_KEYS) parts.push(keys.slice(i, i + PACK_KEYS));
    if (!parts.length) parts.push([]);
    for (let i = 0; i < parts.length; i++) {
      const blob = await C.sealKeySync(this.h.me.id, S.dev, d.id, target, parts[i], Date.now());
      await this.h.api("sync/send", { to: d.id, from: S.dev, blob, last: i === parts.length - 1 });
    }
    keys.forEach((k) => k.key.fill(0));
    this.h.say.ok("Sent " + keys.length + " room key" + (keys.length === 1 ? "" : "s") + " to " + d.name + ", sealed to that device.");
  }

  async receive(p, from) {
    const S = this.store;
    if (!from) { await this.h.api("sync/done", { id: p.id }).catch(() => {}); return; }
    let keys;
    try { keys = await C.openKeySync(S.device, this.myPub(), from.id, S.dev, p.blob); }
    catch (e) { this.h.say.warn("A history package from " + from.name + " was refused: " + e.message + "."); await this.h.api("sync/done", { id: p.id }).catch(() => {}); return; }
    // Each key is accepted only if its room's signed header commits to it (a package can't plant a key).
    const byRoom = new Map();
    for (const k of keys) { if (!byRoom.has(k.room)) byRoom.set(k.room, []); byRoom.get(k.room).push(k); }
    let n = 0;
    for (const [room, list] of byRoom) {
      const info = this.h.room(room);
      if (!info) continue;
      let items;
      try { items = (await this.h.api("rooms/" + room + "/epochs?all=1")).items; } catch (e) { continue; }
      const headers = new Map(items.map((it) => [it.epoch, it]));
      for (const k of list) {
        const it = headers.get(k.epoch);
        const signer = it && this.h.trusted(it.from);
        if (!it || !signer) continue;
        try {
          const { header } = await C.checkEpoch(this.h.me.id, this.h.me.fp, room, it, signer.pub, k.key);
          if (!this.inWindow(info, k.epoch, header.at)) continue;
          await this.keep(room, k.epoch, k.key, header.at);
          n++;
        } catch (e) { /* not this room's key: dropped */ }
      }
    }
    await this.flushAcks();
    await this.h.api("sync/done", { id: p.id }).catch(() => {});
    if (this.h.onKeys) await this.h.onKeys();
    this.h.say.ok("Received " + n + " older room key" + (n === 1 ? "" : "s") + " from " + from.name + ".");
  }

  async removed() {
    await this.store.wipe();
    this.h.store = null;
    if (this.h.onRemoved) this.h.onRemoved();
    this.h.say.warn("This browser was removed from your devices on another device, so the room keys it kept have been wiped (here and in this tab's memory).");
  }
}
