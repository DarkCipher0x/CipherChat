package systems.darkcipher.cipherchat.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.Canon
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.Device
import systems.darkcipher.cipherchat.crypto.DeviceEntry
import systems.darkcipher.cipherchat.crypto.Devices
import systems.darkcipher.cipherchat.crypto.b64
import systems.darkcipher.cipherchat.crypto.hex
import systems.darkcipher.cipherchat.crypto.long
import systems.darkcipher.cipherchat.crypto.longOrNull
import systems.darkcipher.cipherchat.crypto.random
import systems.darkcipher.cipherchat.crypto.sha3_256
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.unb64
import systems.darkcipher.cipherchat.crypto.utf8
import systems.darkcipher.cipherchat.crypto.wipe
import java.io.File

/** Seals the key store file to this phone (the app uses a non-exportable Android Keystore key; tests pass a stand-in). */
interface StoreGuard {
    fun protect(plain: ByteArray): ByteArray
    fun unprotect(sealed: ByteArray): ByteArray
}

/**
 * This phone's key store (PROTOCOL.md §10, KeyStore.cs): room keys this installation has opened, kept so the server
 * can delete its wrapped copies. Each key is sealed twice, by this installation's device key and by a key derived from
 * the person's master secret, and the whole file again by [StoreGuard], so neither a copy of the app's data nor the
 * passphrase alone opens anything. Never uploaded or backed up (the app opts out of Android backup); removing this
 * phone from the device list wipes it. One file per server and person.
 */
class KeyStore private constructor(
    private val file: File, private val guard: StoreGuard, val user: String,
    private val storeKey: ByteArray, private val deviceKey: ByteArray, private val sealedSeed: ByteArray, val device: Device,
    val dev: String, val name: String, val added: Long, listedSeq: Long, isNew: Boolean,
    /** user -> (seq, device ids) of device lists already shown. */
    val seen: MutableMap<String, Pair<Long, List<String>>>,
    private val keys: MutableMap<Pair<String, Long>, Row>,
    /** prekey id -> (expiry, sealed 96-byte seed), PROTOCOL.md §11 */
    private val prekeys: MutableMap<String, Row>,
) {
    private class Row(val at: Long, val sealed: ByteArray)

    private val gate = Any()
    @Volatile var listedSeq = listedSeq; private set
    @Volatile var isNew = isNew; private set

    fun entry(): DeviceEntry = Devices.entry(dev, name, device, added)
    fun code(): String = Devices.code(device.kemPqPk, device.kemEcPk)

    fun get(room: String, epoch: Long): ByteArray? {
        val row = synchronized(gate) { keys[room to epoch] } ?: return null
        return try { Devices.openStored(deviceKey, storeKey, user, room, epoch, row.sealed) } catch (e: CryptoFail) { null }
    }

    fun has(room: String, epoch: Long): Boolean = synchronized(gate) { keys.containsKey(room to epoch) }

    fun put(room: String, epoch: Long, key: ByteArray, at: Long) {
        val s = Devices.sealStored(deviceKey, storeKey, user, room, epoch, key)
        synchronized(gate) { keys[room to epoch] = Row(at, s) }
        save()
    }

    class Item(val room: String, val epoch: Long, val key: ByteArray, val at: Long)

    fun putMany(items: List<Item>) {
        synchronized(gate) { for (x in items) keys[x.room to x.epoch] = Row(x.at, Devices.sealStored(deviceKey, storeKey, user, x.room, x.epoch, x.key)) }
        save()
    }

    class Listed(val room: String, val epoch: Long, val at: Long)

    fun list(): List<Listed> = synchronized(gate) { keys.map { (k, v) -> Listed(k.first, k.second, v.at) } }

    fun drop(items: List<Pair<String, Long>>) {
        val n = synchronized(gate) { items.count { keys.remove(it) != null } }
        if (n > 0) save()
    }

    // ------------------------------------------------------------------------------------------- prekeys (PROTOCOL.md §11)
    private fun prekeyRoom(id: String) = "prekey:$id"

    fun putPrekey(id: String, seed: ByteArray, exp: Long) {
        val s = Devices.sealStored(deviceKey, storeKey, user, prekeyRoom(id), 0, seed)
        synchronized(gate) { prekeys[id] = Row(exp, s) }
        save()
    }

    /** The prekey's 96-byte seed (the caller wipes it), or null once it's erased. */
    fun getPrekey(id: String): ByteArray? {
        val row = synchronized(gate) { prekeys[id] } ?: return null
        return try { Devices.openStored(deviceKey, storeKey, user, prekeyRoom(id), 0, row.sealed, 96) } catch (e: CryptoFail) { null }
    }

    fun listPrekeys(): List<Pair<String, Long>> = synchronized(gate) { prekeys.map { (k, v) -> k to v.at } }

    fun dropPrekeys(ids: List<String>) {
        val n = synchronized(gate) { ids.count { prekeys.remove(it) != null } }
        if (n > 0) save()
    }

    fun listed(seq: Long) { listedSeq = seq; save() }
    fun notNew() { isNew = false; save() }
    fun saveSeen() = save()

    /** This phone stops being a device for this person: every key it held goes. */
    fun wipeAll() {
        synchronized(gate) { keys.clear(); prekeys.clear() }
        erase(file)
        close()
    }

    /** Forgets the keys in memory (the chat locked); the file stays. */
    fun close() = wipe(storeKey, deviceKey)

    private fun save() {
        synchronized(gate) {
            val plain = Canon.bytes(buildJsonObject {
                put("v", 1); put("user", user); put("dev", dev); put("name", name); put("added", added)
                put("listed_seq", listedSeq); put("is_new", isNew)
                put("device_key", b64(deviceKey)); put("seed", b64(sealedSeed))
                put("seen", buildJsonObject {
                    for ((u, v) in seen) put(u, buildJsonObject { put("seq", v.first); put("ids", buildJsonArray { for (x in v.second) add(JsonPrimitive(x)) }) })
                })
                put("keys", buildJsonArray {
                    for ((k, v) in keys.entries.sortedWith(compareBy({ it.key.first }, { it.key.second })))
                        add(buildJsonObject { put("room", k.first); put("epoch", k.second); put("at", v.at); put("s", b64(v.sealed)) })
                })
                put("prekeys", buildJsonArray {
                    for ((id, v) in prekeys.entries.sortedBy { it.key })
                        add(buildJsonObject { put("id", id); put("exp", v.at); put("s", b64(v.sealed)) })
                })
            })
            try {
                file.parentFile?.mkdirs()
                val tmp = File(file.parentFile, file.name + ".tmp")
                tmp.writeBytes(guard.protect(plain))
                check(tmp.renameTo(file) || (file.delete() && tmp.renameTo(file))) { "couldn't save the key store" }
            } finally { wipe(plain) }
        }
    }

    companion object {
        fun pathFor(dir: File, origin: String, user: String): File =
            File(dir, hex(sha3_256(utf8("cipherchat-keystore|$origin|$user"))).substring(0, 32) + ".bin")

        /**
         * Opens (or makes) the store for this person on this server. [storeKey] comes from the unlocked master
         * ([Devices.storeKey]). A store sealed under an earlier identity, or damaged, is wiped and made again.
         */
        fun open(file: File, guard: StoreGuard, user: String, storeKey: ByteArray, name: String): KeyStore {
            if (file.exists()) {
                try { return load(file, guard, user, storeKey) }
                catch (e: Exception) {
                    if (e !is CryptoFail && e !is IllegalArgumentException && e !is IllegalStateException && e !is java.security.GeneralSecurityException &&
                        e !is kotlinx.serialization.SerializationException) throw e
                    erase(file)
                }
            }
            val deviceKey = random(32)
            val seed = Devices.newSeed()
            try {
                return KeyStore(file, guard, user, storeKey.copyOf(), deviceKey, Devices.sealSeed(deviceKey, storeKey, user, seed), Device.fromSeed(seed),
                    Devices.newId(), name, System.currentTimeMillis(), 0, true, HashMap(), HashMap(), HashMap()).also { it.save() }
            } finally { wipe(seed) }
        }

        private fun load(file: File, guard: StoreGuard, user: String, storeKey: ByteArray): KeyStore {
            val plain = guard.unprotect(file.readBytes())
            val o = try { Json.parseToJsonElement(String(plain, Charsets.UTF_8)) as? JsonObject ?: throw CryptoFail("damaged key store") } finally { wipe(plain) }
            if (o.longOrNull("v") != 1L || o.strOrNull("user") != user) throw CryptoFail("not this person's key store")
            val deviceKey = unb64(o.str("device_key"), 32)
            val sealedSeed = unb64(o.str("seed"))
            val seed = Devices.openSeed(deviceKey, storeKey, user, sealedSeed)       // throws under another identity's master
            val device = try { Device.fromSeed(seed) } finally { wipe(seed) }
            val seen = HashMap<String, Pair<Long, List<String>>>()
            (o["seen"] as? JsonObject)?.forEach { (u, v) ->
                val e = v as? JsonObject ?: return@forEach
                seen[u] = e.long("seq") to ((e["ids"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } ?: emptyList())
            }
            val keys = HashMap<Pair<String, Long>, Row>()
            for (k in (o["keys"] as? JsonArray ?: JsonArray(emptyList())).filterIsInstance<JsonObject>())
                keys[k.str("room") to k.long("epoch")] = Row(k.long("at"), unb64(k.str("s")))
            val prekeys = HashMap<String, Row>()
            for (k in (o["prekeys"] as? JsonArray ?: JsonArray(emptyList())).filterIsInstance<JsonObject>())
                prekeys[k.str("id")] = Row(k.long("exp"), unb64(k.str("s")))
            return KeyStore(file, guard, user, storeKey.copyOf(), deviceKey, sealedSeed, device, o.str("dev"), o.str("name"), o.long("added"),
                o.longOrNull("listed_seq") ?: 0, (o["is_new"] as? JsonPrimitive)?.content == "true", seen, keys, prekeys)
        }

        private fun erase(file: File) {
            if (!file.exists()) return
            try { file.writeBytes(ByteArray(file.length().toInt())) } catch (e: java.io.IOException) { }
            file.delete()
        }
    }
}
