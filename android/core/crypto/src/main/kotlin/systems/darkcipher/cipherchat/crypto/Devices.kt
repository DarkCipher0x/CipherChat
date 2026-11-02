package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters

/**
 * One installation's own key pair (PROTOCOL.md §10). Random, never derived from the master, so the identity alone can't
 * rebuild it; its 96-byte seed (ML-KEM d‖z, then the X25519 private key) stays on the device, sealed by the key store.
 */
class Device private constructor(
    internal val kemPq: MLKEMPrivateKeyParameters, val kemPqPk: ByteArray,
    internal val kemEc: X25519PrivateKeyParameters, val kemEcPk: ByteArray,
) {
    companion object {
        fun fromSeed(seed: ByteArray): Device {
            if (seed.size != 96) throw CryptoFail("bad device seed")
            val d = seed.copyOfRange(0, 64)
            try {
                val kem = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, d)
                val x = X25519PrivateKeyParameters(seed, 64)
                return Device(kem, kem.getPublicKey(), x, x.generatePublicKey().encoded)
            } finally { wipe(d) }
        }
    }
}

/** A line on someone's signed device list. */
class DeviceEntry(val id: String, val name: String, val kemPq: String, val kemEc: String, val added: Long)

/** Someone's device list, checked against their trusted identity. */
class DeviceList(val user: String, val fp: String, val seq: Long, val at: Long, val devices: List<DeviceEntry>)

class SyncedKey(val room: String, val epoch: Long, val key: ByteArray)

/** Device lists, the key store's double seal and history-sync packages, as the web chat and Windows make them. */
object Devices {
    private val ID = Regex("^[0-9a-f]{16}$")

    fun newSeed(): ByteArray = random(96)
    fun newId(): String = hex(random(8))

    /** Shown on both devices before history moves: the first 16 hex of SHA3-256(kem_pq ‖ kem_ec), in groups of four. */
    fun code(kemPq: ByteArray, kemEc: ByteArray): String = fpGroups(hex(sha3_256(kemPq, kemEc)).substring(0, 16))

    fun entry(id: String, name: String, d: Device, added: Long) = DeviceEntry(id, name, b64(d.kemPqPk), b64(d.kemEcPk), added)

    fun publish(id: Identity, fp: String, seq: Long, devices: List<DeviceEntry>, at: Long): Signed64 {
        val list = buildJsonArray {
            for (d in devices.sortedBy { it.id }) add(buildJsonObject {
                put("id", d.id); put("name", d.name); put("kem_pq", d.kemPq); put("kem_ec", d.kemEc); put("added", d.added)
            })
        }
        val raw = Canon.bytes(buildJsonObject {
            put("v", 1); put("t", "devices"); put("user", id.user); put("fp", fp); put("seq", seq); put("at", at); put("devices", list)
        })
        return Signed64(b64(raw), b64(sign(id, "dcx-chat/v1/devices", raw)))
    }

    fun open(entry: Signed64, pub: PublicIdentity): DeviceList {
        val sig = Canon.parseSigned(entry.b, 16384 + 4096)
        val o = sig.obj
        val seq = o.longOrNull("seq")
        val arr = o["devices"] as? kotlinx.serialization.json.JsonArray
        if (o.strOrNull("t") != "devices" || o.strOrNull("user") != pub.user || o.strOrNull("fp") != pub.fp || seq == null || seq < 1 || arr == null)
            throw CryptoFail("device list doesn't match the identity")
        if (!verify(pub, "dcx-chat/v1/devices", sig.raw, unb64(entry.s))) throw CryptoFail("device list signature is invalid")
        var prev: String? = null
        val list = arr.map { n ->
            val d = n as? JsonObject ?: throw CryptoFail("malformed device list")
            val id = d.strOrNull("id")
            if (id == null || !ID.matches(id) || (prev != null && prev!! >= id)) throw CryptoFail("malformed device list")
            unb64(d.str("kem_pq"), Sizes.KEM_PQ); unb64(d.str("kem_ec"), Sizes.KEM_EC)
            prev = id
            DeviceEntry(id, d.strOrNull("name") ?: "", d.str("kem_pq"), d.str("kem_ec"), d.longOrNull("added") ?: 0)
        }
        return DeviceList(pub.user, pub.fp, seq, o.longOrNull("at") ?: 0, list)
    }

    // ------------------------------------------------------------------------------------------- the key store
    // aesSeal(deviceKey, aesSeal(storeKey, key, aad), aad). On Android deviceKey is wrapped by a non-exportable
    // Keystore key; storeKey comes from the master, so a copy of the app's data without the passphrase opens nothing.
    fun storeKey(master: ByteArray, user: String): ByteArray = hkdf32(master, utf8(user), "dcx-chat/v1/store-key")

    private fun storeAad(user: String, room: String, epoch: Long) = utf8("dcx-chat/v1/store|$user|$room|$epoch")

    fun sealStored(deviceKey: ByteArray, storeKey: ByteArray, user: String, room: String, epoch: Long, key: ByteArray): ByteArray {
        val aad = storeAad(user, room, epoch)
        return aesSeal(deviceKey, aesSeal(storeKey, key, aad), aad)
    }

    fun openStored(deviceKey: ByteArray, storeKey: ByteArray, user: String, room: String, epoch: Long, sealed: ByteArray, len: Int = 32): ByteArray {
        val aad = storeAad(user, room, epoch)
        val inner = aesOpen(deviceKey, sealed, aad)
        try {
            val key = aesOpen(storeKey, inner, aad)
            if (key.size != len) throw CryptoFail("stored key has the wrong length")
            return key
        } finally { wipe(inner) }
    }

    /** The device's own seed is sealed the same way under a fixed name. */
    fun sealSeed(deviceKey: ByteArray, storeKey: ByteArray, user: String, seed: ByteArray) = sealStored(deviceKey, storeKey, user, "device", 0, seed)
    fun openSeed(deviceKey: ByteArray, storeKey: ByteArray, user: String, sealed: ByteArray) = openStored(deviceKey, storeKey, user, "device", 0, sealed, 96)

    // ------------------------------------------------------------------------------------------- history sync
    private fun syncAad(user: String, from: String, to: String) = utf8("dcx-chat/v1/key-sync|$user|$from|$to")

    /** Room keys for another of my devices: wrap(k, target) ‖ aesSeal(k, u32(len p) ‖ p ‖ sig(p)). Returns base64. */
    fun sealKeySync(id: Identity, from: String, to: String, targetKemPq: ByteArray, targetKemEc: ByteArray, keys: List<SyncedKey>, at: Long): String {
        val p = Canon.bytes(buildJsonObject {
            put("v", 1); put("t", "key-sync"); put("user", id.user); put("from", from); put("to", to); put("at", at)
            put("keys", buildJsonArray { for (k in keys) add(buildJsonObject { put("room", k.room); put("epoch", k.epoch); put("key", b64(k.key)) }) })
        })
        val s = sign(id, "dcx-chat/v1/key-sync", p)
        val k32 = random(32)
        val aad = syncAad(id.user, from, to)
        try { return b64(concat(wrapKey(k32, targetKemPq, targetKemEc, aad), aesSeal(k32, concat(u32be(p.size), p, s), aad))) }
        finally { wipe(k32, p) }
    }

    /** [myPub] is my own trusted identity: the package must be signed by it. */
    fun openKeySync(dev: Device, myPub: PublicIdentity, from: String, to: String, blob: String): List<SyncedKey> {
        val raw = unb64(blob)
        if (raw.size < Sizes.WRAP + 12 + 4 + 16) throw CryptoFail("history package too short")
        val aad = syncAad(myPub.user, from, to)
        val k32 = unwrapKey(raw.copyOfRange(0, Sizes.WRAP), dev.kemPq, dev.kemPqPk, dev.kemEc, dev.kemEcPk, aad)
        val inner = try { aesOpen(k32, raw.copyOfRange(Sizes.WRAP, raw.size), aad) } finally { wipe(k32) }
        try {
            if (inner.size < 4) throw CryptoFail("malformed history package")
            val n = ((inner[0].toLong() and 0xff) shl 24) or ((inner[1].toLong() and 0xff) shl 16) or ((inner[2].toLong() and 0xff) shl 8) or (inner[3].toLong() and 0xff)
            if (n + 4 + Sizes.SIG != inner.size.toLong()) throw CryptoFail("malformed history package")
            val p = inner.copyOfRange(4, 4 + n.toInt())
            if (!verify(myPub, "dcx-chat/v1/key-sync", p, inner.copyOfRange(4 + n.toInt(), inner.size))) throw CryptoFail("history package signature is invalid")
            val o = try { Canon.parseSigned(b64(p), p.size).obj } catch (e: CryptoFail) { throw CryptoFail("history package doesn't match") }
            val arr = o["keys"] as? kotlinx.serialization.json.JsonArray
            if (o.strOrNull("t") != "key-sync" || o.strOrNull("user") != myPub.user || o.strOrNull("from") != from || o.strOrNull("to") != to || arr == null)
                throw CryptoFail("history package doesn't match")
            return arr.map { x ->
                val k = x as? JsonObject ?: throw CryptoFail("history package doesn't match")
                SyncedKey(k.str("room"), k.long("epoch"), unb64(k.str("key"), 32))
            }
        } finally { wipe(inner) }
    }
}
