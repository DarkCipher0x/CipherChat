package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.Canon
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.Device
import systems.darkcipher.cipherchat.crypto.DeviceEntry
import systems.darkcipher.cipherchat.crypto.Prekey
import systems.darkcipher.cipherchat.crypto.Prekeys
import systems.darkcipher.cipherchat.crypto.DeviceList
import systems.darkcipher.cipherchat.crypto.Devices
import systems.darkcipher.cipherchat.crypto.PublicIdentity
import systems.darkcipher.cipherchat.crypto.Signed64
import systems.darkcipher.cipherchat.crypto.Sizes
import systems.darkcipher.cipherchat.crypto.SyncedKey
import systems.darkcipher.cipherchat.crypto.arr
import systems.darkcipher.cipherchat.crypto.long
import systems.darkcipher.cipherchat.crypto.longOrNull
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.unb64
import systems.darkcipher.cipherchat.crypto.wipe
import systems.darkcipher.cipherchat.crypto.Room as RoomCrypto

/**
 * Devices, the key store and history (history.js, KeyHistory.cs; PROTOCOL.md §10, PREKEYS-DESIGN.md phase 1):
 *   - this phone joins the person's signed device list, keeps the room keys it opens, and acknowledges them, so the
 *     server can delete its wrapped copies;
 *   - a new phone asks the person's other devices for older keys; they ask the person first and show a device code;
 *   - device lists are checked against the owner's trust like everything else, and changes are shown;
 *   - each room's history window is applied to the keys kept here.
 */
internal class KeyHistory(private val e: ChatEngine) {
    private val pending = HashMap<String, MutableSet<Long>>()
    private val asked = HashSet<String>()
    private val busy = Mutex()
    @Volatile private var ackJob: Job? = null
    private val preCache = HashMap<String, Device>()        // prekey id -> its key pair, while unlocked
    @Volatile private var preChecked = 0L

    private val store: KeyStore? get() = e.store
    private val myPub get() = PublicIdentity(e.me.user, e.me.fp, 0, e.me.id.kemPqPk, e.me.id.kemEcPk, e.me.id.sigPqPk, e.me.id.sigEcPk)

    private fun entryOf(user: String): JsonObject? =
        e.state.arr("directory").filterIsInstance<JsonObject>().firstOrNull { it.strOrNull("user") == user }?.get("devices") as? JsonObject

    private fun signed(o: JsonObject) = Signed64(o.str("b"), o.str("s"))
    private fun listJson(s: Signed64) = buildJsonObject { put("b", s.b); put("s", s.s) }

    fun myList(): DeviceList? {
        val entry = entryOf(e.myUser) ?: return null
        return try { Devices.open(signed(entry), myPub) }
        catch (x: CryptoFail) {
            e.say(null, LineKind.ERR, "Your device list on the server doesn't verify (" + x.message + "). It won't be used or changed until that's fixed.")
            throw x
        }
    }

    /** Joins this phone to the device list (once), says hello, and asks other devices for history if it's new here. */
    suspend fun enroll() {
        val s = store ?: return
        var others: List<DeviceEntry> = emptyList()
        for (attempt in 0 until 3) {
            val list = myList()
            if (list != null && list.devices.any { it.id == s.dev }) { others = emptyList(); break }
            if (list != null && s.listedSeq > 0 && list.seq > s.listedSeq) { removed(); return }   // another device removed this phone
            val cur = list?.devices?.toMutableList() ?: mutableListOf()
            if (cur.size >= MAX_DEVICES) {
                val seen = (e.state["me"] as? JsonObject)?.get("device_seen") as? JsonObject
                val gone = cur.minBy { (seen?.get(it.id) as? JsonPrimitive)?.longOrNull ?: 0 }
                cur.remove(gone)
                e.say(null, LineKind.WARN, "Your device list was full, so the least recently used device (" + gone.name + ") was removed from it.")
            }
            others = cur
            val seq = (list?.seq ?: 0) + 1
            val signed = Devices.publish(e.me.id, e.me.fp, seq, cur + s.entry(), System.currentTimeMillis())
            try {
                e.api.call("keydevices", buildJsonObject { put("list", listJson(signed)); put("dev", s.dev) })
                s.listed(seq)
                e.refresh()
                break
            } catch (x: ApiException) {
                if (!x.flag("stale")) throw x
                e.refresh()
            }
        }
        e.api.call("store/hello", buildJsonObject { put("dev", s.dev) })
        if (s.isNew) {
            if (others.isNotEmpty()) {
                e.api.call("sync/request", buildJsonObject { put("dev", s.dev) })
                e.say(null, LineKind.SYS, "Asked your other devices for this phone's history. Approve it on one of them, and check it shows this code: " + s.code())
            }
            s.notNew()
        }
    }

    /** Every state change: device lists (shown when they change), my own membership, sync work. */
    suspend fun onState() {
        if (!busy.tryLock()) return
        try {
            checkLists()
            val waiting = ((e.state["me"] as? JsonObject)?.get("sync_waiting") as? JsonPrimitive)?.longOrNull ?: 0
            if (store != null && waiting > 0) syncWork()
            if (store != null && preChecked > 0 && System.currentTimeMillis() - preChecked > PREKEY_CHECK_MS) prekeys()
        } catch (x: Exception) {
            if (x !is ApiException && x !is CryptoFail && x !is IllegalStateException) throw x
            e.say(null, LineKind.ERR, "Device and history check failed: " + x.message)
        } finally { busy.unlock() }
    }

    private fun checkLists() {
        val s = store
        val seen = s?.seen ?: HashMap()
        var changed = false
        for (d in e.state.arr("directory").filterIsInstance<JsonObject>()) {
            val entry = d["devices"] as? JsonObject ?: continue
            val user = d.str("user")
            val mine = user == e.myUser
            val pub = if (mine) myPub else e.trusted(user)?.pub ?: continue
            val list = try { Devices.open(signed(entry), pub) }
                       catch (x: CryptoFail) { e.say(null, LineKind.WARN, user + "'s device list doesn't verify (" + x.message + "): ignored."); continue }
            val ids = list.devices.map { it.id }
            val before = seen[user]
            if (before != null && list.seq < before.first) {
                e.say(null, LineKind.WARN, user + "'s device list went back to an older version (" + list.seq + " after " + before.first + "). The server may be replaying it.")
                continue
            }
            if (before != null && before.first != list.seq) {
                val added = list.devices.filter { it.id !in before.second }.map { it.name }
                val removed = before.second.size - ids.count { it in before.second }
                if (added.isNotEmpty())
                    e.say(null, if (mine) LineKind.WARN else LineKind.SYS, (if (mine) "A device was added to your account" else "$user added a device") + ": " +
                        added.joinToString(", ") + if (mine) ". If that wasn't you, reset your identity." else ".")
                if (removed > 0) e.say(null, LineKind.SYS, (if (mine) "You" else user) + " removed " + removed + " device" + (if (removed > 1) "s" else "") + ".")
            }
            if (before == null || before.first != list.seq) { seen[user] = list.seq to ids; changed = true }
            if (mine && s != null && s.listedSeq > 0 && list.seq > s.listedSeq && s.dev !in ids) { removed(); return }
        }
        if (s != null && changed) s.saveSeen()
    }

    // ------------------------------------------------------------------------------------------- keys: kept, acknowledged, windowed
    fun kept(room: String, epoch: Long): ByteArray? = store?.get(room, epoch)

    fun keep(room: String, epoch: Long, key: ByteArray, at: Long) {
        val s = store ?: return
        s.put(room, epoch, key, at)
        pendingAdd(room, epoch)
        ackJob?.cancel()
        ackJob = e.scope.launch { delay(300); flushAcks() }
    }

    private fun pendingAdd(room: String, epoch: Long) { synchronized(pending) { pending.getOrPut(room) { HashSet() }.add(epoch) } }

    suspend fun flushAcks() {
        val s = store ?: return
        val work = synchronized(pending) { pending.map { it.key to it.value.toList() }.also { pending.clear() } }
        for ((room, epochs) in work) for (part in epochs.chunked(1000)) {
            try {
                e.api.call("rooms/$room/ack", buildJsonObject { put("dev", s.dev); put("epochs", buildJsonArray { for (x in part) add(JsonPrimitive(x)) }) })
            } catch (x: ApiException) { if (x.status != 404) for (ep in part) pendingAdd(room, ep) }
        }
    }

    /** Keys past a room's history window (never the current one) and keys of rooms I'm no longer in are erased. */
    fun applyWindow(): List<Pair<String, Long>> {
        val s = store ?: return emptyList()
        val rooms = e.state.arr("rooms").filterIsInstance<JsonObject>().associateBy { it.str("id") }
        val gone = s.list().filter { !inWindow(rooms[it.room], it.epoch, it.at) }.map { it.room to it.epoch }
        s.drop(gone)
        return gone
    }

    // ------------------------------------------------------------------------------------------- prekeys (protocol 2, PROTOCOL.md §11)
    fun prekeyOf(id: String): Device? {
        val s = store ?: return null
        synchronized(preCache) { preCache[id] }?.let { return it }
        val seed = s.getPrekey(id) ?: return null
        val pair = try { Device.fromSeed(seed) } finally { wipe(seed) }
        synchronized(preCache) { preCache[id] = pair }
        return pair
    }

    fun forgetPrekeys() = synchronized(preCache) { preCache.clear() }

    /** Publishes a new prekey when the newest is a day old (or the server lost it), and erases expired ones, but only
     *  after opening and keeping every room key still wrapped to them. After unlocking, then hourly. Without [erase]
     *  it only publishes (at unlock, before the import has run). */
    suspend fun prekeys(erase: Boolean = true) {
        val s = store ?: return
        val now = System.currentTimeMillis()
        preChecked = now
        val mine = s.listPrekeys()
        val expired = mine.filter { it.second <= now }.map { it.first }
        if (erase && expired.isNotEmpty()) {
            e.importAll()
            s.dropPrekeys(expired)
            synchronized(preCache) { expired.forEach { preCache.remove(it) } }
        }
        val live = mine.filter { it.second > now }.sortedByDescending { it.second }
        val entry = e.state.arr("directory").filterIsInstance<JsonObject>().firstOrNull { it.strOrNull("user") == e.myUser }
        val onServer = (entry?.get("prekeys") as? JsonArray ?: JsonArray(emptyList())).filterIsInstance<JsonObject>()
            .mapNotNull { try { Canon.parseSigned(it.str("b"), 4096, Canon.V2).obj.str("id") } catch (x: CryptoFail) { null } }.toSet()
        var pub: Triple<String, Device, Long>? = null
        if (live.isEmpty() || now - (live[0].second - Prekeys.LIFE_MS) >= PREKEY_EVERY_MS) {
            val id = Prekeys.newId()
            val seed = Devices.newSeed()
            val pair = try { s.putPrekey(id, seed, now + Prekeys.LIFE_MS); Device.fromSeed(seed) } finally { wipe(seed) }
            synchronized(preCache) { preCache[id] = pair }
            pub = Triple(id, pair, now)
        } else if (live[0].first !in onServer) {
            prekeyOf(live[0].first)?.let { pub = Triple(live[0].first, it, live[0].second - Prekeys.LIFE_MS) }
        }
        val p = pub ?: return
        val signed = Prekeys.publish(e.me.id, e.me.fp, s.dev, p.first, p.second, p.third)
        e.api.call("keydevices/prekey", buildJsonObject { put("dev", s.dev); put("prekey", listJson(signed)) })
        e.refresh()
    }

    /** True unless a verified device list of this person (seen here) leaves the device out. */
    fun deviceListed(user: String, dev: String): Boolean {
        val seen = store?.seen?.get(user) ?: return true
        return dev in seen.second
    }

    /** The lines of a per-device room key for these people, or why it can't be made (PROTOCOL.md §11): each person's
     *  device list and every listed device's newest prekey must verify against their trusted identity. */
    fun v2Lines(users: List<String>): Pair<List<RoomCrypto.DeviceLine>?, String?> {
        if (store == null) return null to "this phone keeps no room keys"
        val lines = ArrayList<RoomCrypto.DeviceLine>()
        val now = System.currentTimeMillis()
        for (u in users) {
            val d = e.state.arr("directory").filterIsInstance<JsonObject>().firstOrNull { it.strOrNull("user") == u }
            val pub = if (u == e.myUser) myPub else e.trusted(u)?.pub
            if (d == null || pub == null) return null to "$u isn't verified"
            val devs = d["devices"] as? JsonObject ?: return null to "$u has no device list yet"
            if ((d["v2"] as? JsonPrimitive)?.content != "true") return null to "$u has an older app signed in"
            val list = try { Devices.open(signed(devs), pub) } catch (x: CryptoFail) { return null to "$u's device list doesn't verify" }
            val ids = list.devices.map { it.id }
            val best = HashMap<String, Prekey>()
            for (x in (d["prekeys"] as? JsonArray ?: JsonArray(emptyList())).filterIsInstance<JsonObject>()) {
                val pk = try { Prekeys.open(signed(x), pub, ids, now) } catch (ex: CryptoFail) { continue }
                val cur = best[pk.dev]
                if (cur == null || pk.at > cur.at) best[pk.dev] = pk
            }
            for (x in list.devices) {
                val pk = best[x.id] ?: return null to "$u's device “${x.name}” has no fresh prekey"
                lines.add(RoomCrypto.DeviceLine(u, pub.fp, x.id, pk))
            }
        }
        if (lines.size > V2_MAX_DEVICES) return null to "the room has more than $V2_MAX_DEVICES devices"
        return lines to null
    }

    // ------------------------------------------------------------------------------------------- history sync
    private suspend fun syncWork() {
        val s = store!!
        val st = e.api.call("sync?dev=" + s.dev)
        val byId = (myList()?.devices ?: emptyList()).associateBy { it.id }
        for (p in st.arr("packages").filterIsInstance<JsonObject>()) receive(p, byId[p.str("from")])
        for (r in st.arr("requests").filterIsInstance<JsonObject>()) {
            val id = r.str("id")
            if (!asked.add(id)) continue
            val d = byId[r.str("dev")] ?: continue
            val ask = e.confirmSync ?: continue
            val code = Devices.code(unb64(d.kemPq), unb64(d.kemEc))
            when (ask(d.name, d.added, code)) {
                true -> send(d)
                false -> try { e.api.call("sync/decline", buildJsonObject { put("id", id) }) } catch (x: ApiException) { }
                null -> {}
            }
        }
    }

    private suspend fun send(d: DeviceEntry) {
        val s = store!!
        val rooms = e.state.arr("rooms").filterIsInstance<JsonObject>().associateBy { it.str("id") }
        val keys = ArrayList<SyncedKey>()
        for (x in s.list()) {
            val info = rooms[x.room] ?: continue
            if ((info["history_sync"] as? JsonPrimitive)?.content == "false" || !inWindow(info, x.epoch, x.at)) continue
            s.get(x.room, x.epoch)?.let { keys.add(SyncedKey(x.room, x.epoch, it)) }
        }
        keys.sortWith(compareBy({ it.room }, { it.epoch }))
        val kemPq = unb64(d.kemPq, Sizes.KEM_PQ); val kemEc = unb64(d.kemEc, Sizes.KEM_EC)
        try {
            val parts = keys.chunked(PACK_KEYS).ifEmpty { listOf(emptyList()) }
            for ((i, part) in parts.withIndex()) {
                val blob = Devices.sealKeySync(e.me.id, s.dev, d.id, kemPq, kemEc, part, System.currentTimeMillis())
                e.api.call("sync/send", buildJsonObject { put("to", d.id); put("from", s.dev); put("blob", blob); put("last", i == parts.size - 1) })
            }
        } finally { for (k in keys) wipe(k.key) }
        e.say(null, LineKind.OK, "Sent " + keys.size + " room key" + (if (keys.size == 1) "" else "s") + " to " + d.name + ", sealed to that device.")
    }

    private suspend fun done(id: String) { try { e.api.call("sync/done", buildJsonObject { put("id", id) }) } catch (x: ApiException) { } }

    private suspend fun receive(p: JsonObject, from: DeviceEntry?) {
        val s = store!!
        val id = p.str("id")
        if (from == null) { done(id); return }
        val keys = try { Devices.openKeySync(s.device, myPub, from.id, s.dev, p.str("blob")) }
                   catch (x: CryptoFail) { e.say(null, LineKind.WARN, "A history package from " + from.name + " was refused: " + x.message + "."); done(id); return }
        // Each key is accepted only if its room's signed header commits to it (a package can't plant a key)
        var n = 0
        for ((room, group) in keys.groupBy { it.room }) {
            val info = e.roomById(room)?.info ?: continue
            val res = try { e.api.call("rooms/$room/epochs?all=1") } catch (x: ApiException) { continue }
            val headers = res.arr("items").filterIsInstance<JsonObject>().associateBy { it.long("epoch") }
            val kept = ArrayList<KeyStore.Item>()
            for (k in group) {
                val it = headers[k.epoch] ?: continue
                val signer = e.trusted(it.str("from")) ?: continue
                try {
                    val b = it.obj("body")
                    val o = RoomCrypto.checkEpoch(room, k.epoch, it.str("from"), b.str("h"), b.str("s"), signer.pub!!, k.key)
                    val at = o.header.long("at")
                    if (!inWindow(info, k.epoch, at)) continue
                    kept.add(KeyStore.Item(room, k.epoch, k.key, at))
                } catch (x: CryptoFail) { /* not this room's key: dropped */ }
            }
            s.putMany(kept)                                    // saved first: an ack lets the server delete its wrap
            for (k in kept) pendingAdd(room, k.epoch)
            n += kept.size
        }
        for (k in keys) wipe(k.key)
        flushAcks()
        done(id)
        e.keysArrived()
        e.say(null, LineKind.OK, "Received " + n + " older room key" + (if (n == 1) "" else "s") + " from " + from.name + ".")
    }

    fun removed() {
        store?.wipeAll()
        e.storeRemoved()
        e.say(null, LineKind.WARN, "This phone was removed from your devices on another device, so the room keys it kept have been wiped (in storage and in memory).")
    }

    // ------------------------------------------------------------------------------------------- the person's own actions
    suspend fun askAgain() {
        val s = store ?: throw IllegalStateException("This phone keeps no room keys.")
        e.api.call("sync/request", buildJsonObject { put("dev", s.dev) })
        e.say(null, LineKind.SYS, "Asked your other devices again. Approve it on one of them; this phone's code is " + s.code() + ".")
    }

    suspend fun remove(list: DeviceList, d: DeviceEntry) {
        val rest = list.devices.filter { it.id != d.id }
        if (rest.isEmpty()) throw IllegalStateException("A device list needs at least one device. Keep this one, or reset your identity to start again.")
        val signed = Devices.publish(e.me.id, e.me.fp, list.seq + 1, rest, System.currentTimeMillis())
        e.api.call("keydevices", buildJsonObject { put("list", listJson(signed)) })
        val s = store
        if (s != null && d.id == s.dev) {
            s.wipeAll()
            e.storeRemoved()
            e.say(null, LineKind.WARN, "This phone's key store is wiped; this session keeps nothing from now on.")
        } else e.say(null, LineKind.OK, d.name + " was removed from your devices.")
        e.refresh()
    }

    companion object {
        const val MAX_DEVICES = 16
        private const val PACK_KEYS = 1500              // keys per history package (stays under the server's 192 KiB per blob)
        const val GRACE_DAYS = 7                        // the server deletes a wrap no device acknowledged after this long
        private const val PREKEY_EVERY_MS = 86400 * 1000L   // a new prekey each day (each lives 7 days)
        private const val PREKEY_CHECK_MS = 3600 * 1000L    // how often a long-running session looks again
        const val V2_MAX_DEVICES = 64                   // per-device room keys for at most this many devices (the server's limit)

        /** Wraps for me the server still has past the grace period (PREKEYS-DESIGN §4.2), from an epochs?all=1 listing.
         *  One day of slack covers the server's sweep interval and clock drift. */
        fun leftover(items: JsonArray): Int {
            val cutoff = System.currentTimeMillis() / 1000 - (GRACE_DAYS + 1) * 86400L
            return items.filterIsInstance<JsonObject>().count { (it["body"] as? JsonObject)?.strOrNull("w") != null && (it.longOrNull("at") ?: Long.MAX_VALUE) < cutoff }
        }

        fun leftoverWarning(n: Int) =
            "The server still holds $n " + (if (n == 1) "copy" else "copies") + " of this room's keys for you that are more than $GRACE_DAYS " +
                "days old; it should have deleted them. That happens while an older CipherChat app of yours is still signed in or paired: " +
                "update or remove it (Settings → Paired devices). If none is, the server isn't deleting them as it should."

        fun inWindow(info: JsonObject?, epoch: Long, atMs: Long): Boolean {
            if (info == null) return false
            val days = info.longOrNull("history_days") ?: 0
            if (epoch == (info.longOrNull("epoch") ?: 0) || days == 0L) return true
            return atMs >= System.currentTimeMillis() - days * 86400 * 1000
        }
    }
}
