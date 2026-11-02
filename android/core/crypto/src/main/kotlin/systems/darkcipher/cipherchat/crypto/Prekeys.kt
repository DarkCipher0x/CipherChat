package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Someone's published prekey, checked against their trusted identity and device list. Raw public keys. */
class Prekey(val dev: String, val id: String, val at: Long, val exp: Long, val kemPq: ByteArray, val kemEc: ByteArray)

/**
 * Prekeys (PROTOCOL.md §11): a random ML-KEM-1024 + X25519 pair like the device key (same 96-byte seed, Device.fromSeed),
 * published signed for 7 days and erased by its device when it expires, so nothing the identity can rebuild opens a v2 wrap.
 */
object Prekeys {
    const val LIFE_MS = 7 * 86400 * 1000L
    private const val LIFE_MAX_MS = 8 * 86400 * 1000L
    private const val MARGIN_MS = 3600 * 1000L           // an hour of life left, at least, to be used for a new room key
    private val ID = Regex("^[0-9a-f]{16}$")

    fun newId(): String = hex(random(8))

    fun publish(id: Identity, fp: String, dev: String, pid: String, pre: Device, at: Long): Signed64 {
        val raw = Canon.bytes(buildJsonObject {
            put("v", 2); put("t", "prekey"); put("user", id.user); put("fp", fp); put("dev", dev); put("id", pid); put("at", at)
            put("exp", at + LIFE_MS); put("kem_pq", b64(pre.kemPqPk)); put("kem_ec", b64(pre.kemEcPk))
        })
        return Signed64(b64(raw), b64(sign(id, "dcx-chat/v2/prekey", raw)))
    }

    /** [listedIds]: the device ids on the owner's verified device list. */
    fun open(entry: Signed64, pub: PublicIdentity, listedIds: Collection<String>, now: Long): Prekey {
        val sig = Canon.parseSigned(entry.b, 4096, Canon.V2)
        val o = sig.obj
        val dev = o.strOrNull("dev"); val pid = o.strOrNull("id"); val at = o.longOrNull("at"); val exp = o.longOrNull("exp")
        if (o.strOrNull("t") != "prekey" || o.strOrNull("user") != pub.user || o.strOrNull("fp") != pub.fp ||
            dev == null || dev !in listedIds || pid == null || !ID.matches(pid) || at == null || exp == null ||
            exp - at > LIFE_MAX_MS || exp - now < MARGIN_MS) throw CryptoFail("prekey doesn't match or has expired")
        val kemPq = unb64(o.str("kem_pq"), Sizes.KEM_PQ)
        val kemEc = unb64(o.str("kem_ec"), Sizes.KEM_EC)
        if (!verify(pub, "dcx-chat/v2/prekey", sig.raw, unb64(entry.s))) throw CryptoFail("prekey signature is invalid")
        return Prekey(dev, pid, at, exp, kemPq, kemEc)
    }
}
