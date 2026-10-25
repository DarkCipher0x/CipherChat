package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Room keys ("epochs") and messages, exactly as the web chat makes and checks them. */
object Room {
    private val PAD_BUCKETS = intArrayOf(256, 1024, 4096, 16384)
    val MAX_TEXT_BYTES = PAD_BUCKETS.last() - 4 - 64

    private fun wrapAad(room: String, epoch: Long, u: String, fp: String) = utf8("dcx-chat/v1/wrap|$room|$epoch|$u|$fp")
    private fun commitOf(room: String, epoch: Long, key: ByteArray) = hex(sha3_256(utf8("dcx-chat/v1/epoch-commit|$room|$epoch|"), key))
    fun headerHash(raw: ByteArray): String = hex(sha3_256(raw))

    class Recipient(val u: String, val fp: String, val pub: PublicIdentity)
    class EpochPkg(val h: String, val s: String, val w: Map<String, String>)
    class Built(val pkg: EpochPkg, val key: ByteArray)
    class Opened(val key: ByteArray, val header: JsonObject, val raw: ByteArray)

    fun buildEpoch(me: Identity, myFp: String, room: String, epoch: Long, recipients: List<Recipient>, prev: String): Built {
        val key = random(32)
        val w = LinkedHashMap<String, String>()
        val lines = buildJsonArray {
            for (r in recipients) {
                val wrapped = wrapKey(key, r.pub.kemPq, r.pub.kemEc, wrapAad(room, epoch, r.u, r.fp))
                w[r.u] = b64(wrapped)
                add(buildJsonObject { put("u", r.u); put("fp", r.fp); put("w", hex(sha3_256(wrapped))) })
            }
        }
        val raw = Canon.bytes(buildJsonObject {
            put("v", 1); put("t", "epoch"); put("room", room); put("epoch", epoch); put("by", me.user); put("by_fp", myFp)
            put("at", System.currentTimeMillis()); put("prev", prev); put("recipients", lines); put("commit", commitOf(room, epoch, key))
        })
        return Built(EpochPkg(b64(raw), b64(sign(me, "dcx-chat/v1/epoch", raw)), w), key)
    }

    /**
     * An epoch item from the server (only MY wrapped copy, [myWrap]). [signer] must be the TRUSTED identity of the
     * item's sender; the caller checks trust. Refuses unless the signature, my line, the wrap hash and the key
     * commitment all match.
     */
    fun openEpoch(me: Identity, myFp: String, room: String, itemEpoch: Long, itemFrom: String,
                  h: String, s: String, myWrap: String?, signer: PublicIdentity): Opened {
        val sig = Canon.parseSigned(h, 65536)
        val o = sig.obj
        if (o.str("t") != "epoch" || o.str("room") != room || o.long("epoch") != itemEpoch || o.str("by") != itemFrom ||
            o.str("by") != signer.user || o.str("by_fp") != signer.fp) throw CryptoFail("room key header doesn't match")
        if (!verify(signer, "dcx-chat/v1/epoch", sig.raw, unb64(s))) throw CryptoFail("room key signature is invalid")
        val line = o.arr("recipients").map { it as? JsonObject ?: throw CryptoFail("malformed recipients") }.firstOrNull { it.strOrNull("u") == me.user }
        if (line == null || line.str("fp") != myFp || myWrap == null) throw CryptoFail("this room key wasn't made for your current identity")
        val wrapped = unb64(myWrap, Sizes.WRAP)
        if (hex(sha3_256(wrapped)) != line.str("w")) throw CryptoFail("wrapped key doesn't match the signed header")
        val key = unwrapKey(wrapped, me, wrapAad(room, itemEpoch, me.user, myFp))
        if (commitOf(room, itemEpoch, key) != o.str("commit")) throw CryptoFail("room key commitment mismatch")
        return Opened(key, o, sig.raw)
    }

    // ------------------------------------------------------------------------------------------- messages
    private fun pad(data: ByteArray): ByteArray {
        val size = PAD_BUCKETS.firstOrNull { it >= data.size + 4 } ?: throw CryptoFail("message too long")
        return ByteArray(size).also { u32be(data.size).copyInto(it); data.copyInto(it, 4) }
    }
    private fun unpad(p: ByteArray): ByteArray {
        if (p.size < 4) throw CryptoFail("bad padding")
        val n = ((p[0].toLong() and 0xff) shl 24) or ((p[1].toLong() and 0xff) shl 16) or ((p[2].toLong() and 0xff) shl 8) or (p[3].toLong() and 0xff)
        if (n > p.size - 4) throw CryptoFail("bad padding")
        return p.copyOfRange(4, 4 + n.toInt())
    }
    private fun msgKey(roomKey: ByteArray, room: String, epoch: Long, id: String) = hkdf32(roomKey, utf8(id), "dcx-chat/v1/msg|$room|$epoch")
    private fun sigInput(h: ByteArray, c: ByteArray) = concat(u32be(h.size), h, c)

    class SealedMsg(val h: String, val c: String, val s: String)
    class OpenedMsg(val header: JsonObject, val payload: JsonObject) {
        val text: String get() = payload.str("text")
        val kind: String get() = payload.strOrNull("k") ?: "text"
        val id: String get() = header.str("id")
    }

    fun sealMessage(me: Identity, myFp: String, room: String, epoch: Long, roomKey: ByteArray, payload: JsonObject): SealedMsg {
        val id = b64url(random(16))
        val h = Canon.bytes(buildJsonObject {
            put("v", 1); put("t", "msg"); put("room", room); put("epoch", epoch); put("from", me.user); put("from_fp", myFp)
            put("id", id); put("at", System.currentTimeMillis())
        })
        val mk = msgKey(roomKey, room, epoch, id)
        try {
            val c = aesSeal(mk, pad(Canon.bytes(payload)), h)
            return SealedMsg(b64(h), b64(c), b64(sign(me, "dcx-chat/v1/msg", sigInput(h, c))))
        } finally { wipe(mk) }
    }

    fun text(text: String, kind: String = "text"): JsonObject = buildJsonObject { put("k", kind); put("text", text) }

    /** [sender] must be the TRUSTED identity of the item's sender. */
    fun openMessage(itemRoom: String, itemEpoch: Long, itemFrom: String, h: String, c: String, s: String,
                    roomKey: ByteArray, sender: PublicIdentity): OpenedMsg {
        val sig = Canon.parseSigned(h, 2048)
        val o = sig.obj
        if (o.str("t") != "msg" || o.str("room") != itemRoom || o.long("epoch") != itemEpoch || o.str("from") != itemFrom ||
            o.str("from") != sender.user || o.str("from_fp") != sender.fp) throw CryptoFail("message header doesn't match")
        val ct = unb64(c)
        if (!verify(sender, "dcx-chat/v1/msg", sigInput(sig.raw, ct), unb64(s))) throw CryptoFail("message signature is invalid")
        val mk = msgKey(roomKey, itemRoom, itemEpoch, o.str("id"))
        try {
            val plain = aesOpen(mk, ct, sig.raw)
            val payload = try { Json.parseToJsonElement(String(unpad(plain), Charsets.UTF_8)) } catch (e: Exception) { throw CryptoFail("malformed message") }
            if (payload !is JsonObject || (payload["text"] as? JsonPrimitive)?.isString != true) throw CryptoFail("malformed message")
            return OpenedMsg(o, Payload.check(payload))
        } finally { wipe(mk) }
    }
}
