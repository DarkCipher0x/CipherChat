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

    /**
     * The same checks for a room key this device already holds (its wrap may be gone from the server): the header must
     * be signed by the trusted maker and commit to exactly this key. Either header version.
     */
    fun checkEpoch(room: String, itemEpoch: Long, itemFrom: String, h: String, s: String, signer: PublicIdentity, key: ByteArray): Opened {
        val sig = Canon.parseSigned(h, 65536, Canon.V1V2)
        val o = sig.obj
        if (o.str("t") != "epoch" || o.str("room") != room || o.long("epoch") != itemEpoch || o.str("by") != itemFrom ||
            o.str("by") != signer.user || o.str("by_fp") != signer.fp) throw CryptoFail("room key header doesn't match")
        val label = if (o.long("v") == 2L) "dcx-chat/v2/epoch" else "dcx-chat/v1/epoch"
        if (!verify(signer, label, sig.raw, unb64(s))) throw CryptoFail("room key signature is invalid")
        if (key.size != 32 || commitOf(room, itemEpoch, key) != o.str("commit")) throw CryptoFail("room key commitment mismatch")
        return Opened(key, o, sig.raw)
    }

    /**
     * The hash of a room key's header this device can't open (sealed to other devices, or made before it joined), once
     * its signature checks out: the next key made here still names it as "prev", so the key history stays one chain.
     */
    fun headerHashOf(room: String, itemEpoch: Long, itemFrom: String, h: String, s: String, signer: PublicIdentity): String {
        val sig = Canon.parseSigned(h, 65536, Canon.V1V2)
        val o = sig.obj
        if (o.str("t") != "epoch" || o.str("room") != room || o.long("epoch") != itemEpoch || o.str("by") != itemFrom ||
            o.str("by") != signer.user || o.str("by_fp") != signer.fp) throw CryptoFail("room key header doesn't match")
        val label = if (o.long("v") == 2L) "dcx-chat/v2/epoch" else "dcx-chat/v1/epoch"
        if (!verify(signer, label, sig.raw, unb64(s))) throw CryptoFail("room key signature is invalid")
        return headerHash(sig.raw)
    }

    // ------------------------------------------------------------------------------------------- per-device room keys (PROTOCOL.md §11)
    private fun wrapAadV2(room: String, epoch: Long, u: String, fp: String, dev: String, pid: String) =
        utf8("dcx-chat/v2/wrap|$room|$epoch|$u|$fp|$dev|$pid")

    /** One listed device of a recipient and the prekey it published. */
    class DeviceLine(val u: String, val fp: String, val dev: String, val prekey: Prekey)

    /** One line per listed device of every recipient (any order); the package's w is keyed "user|dev". */
    fun buildEpochV2(me: Identity, myFp: String, room: String, epoch: Long, lines: List<DeviceLine>, prev: String): Built {
        val key = random(32)
        val w = LinkedHashMap<String, String>()
        val rec = buildJsonArray {
            for (l in lines.sortedWith(compareBy<DeviceLine> { it.u }.thenBy { it.dev })) {
                val wrapped = wrapKey(key, l.prekey.kemPq, l.prekey.kemEc, wrapAadV2(room, epoch, l.u, l.fp, l.dev, l.prekey.id))
                w[l.u + "|" + l.dev] = b64(wrapped)
                add(buildJsonObject { put("u", l.u); put("fp", l.fp); put("dev", l.dev); put("prekey", l.prekey.id); put("w", hex(sha3_256(wrapped))) })
            }
        }
        val raw = Canon.bytes(buildJsonObject {
            put("v", 2); put("t", "epoch"); put("room", room); put("epoch", epoch); put("by", me.user); put("by_fp", myFp)
            put("at", System.currentTimeMillis()); put("prev", prev); put("recipients", rec); put("commit", commitOf(room, epoch, key))
        })
        return Built(EpochPkg(b64(raw), b64(sign(me, "dcx-chat/v2/epoch", raw)), w), key)
    }

    /**
     * A v2 epoch item with this device's wrap. [prekeyOf] gives this device's prekey secret by id, or null once it's
     * erased (then nothing opens: that's the point).
     */
    fun openEpochV2(me: Identity, myFp: String, myDev: String, room: String, itemEpoch: Long, itemFrom: String,
                    h: String, s: String, myWrap: String?, signer: PublicIdentity, prekeyOf: (String) -> Device?): Opened {
        val sig = Canon.parseSigned(h, 65536, Canon.V2)
        val o = sig.obj
        if (o.str("t") != "epoch" || o.str("room") != room || o.long("epoch") != itemEpoch || o.str("by") != itemFrom ||
            o.str("by") != signer.user || o.str("by_fp") != signer.fp) throw CryptoFail("room key header doesn't match")
        if (!verify(signer, "dcx-chat/v2/epoch", sig.raw, unb64(s))) throw CryptoFail("room key signature is invalid")
        val line = o.arr("recipients").map { it as? JsonObject ?: throw CryptoFail("malformed recipients") }
            .firstOrNull { it.strOrNull("u") == me.user && it.strOrNull("dev") == myDev }
        if (line == null || line.str("fp") != myFp || myWrap == null)
            throw CryptoFail("this room key wasn't made for this device and your current identity")
        val pid = line.str("prekey")
        val pre = prekeyOf(pid) ?: throw CryptoFail("this device no longer has the prekey this room key was sealed to")
        val wrapped = unb64(myWrap, Sizes.WRAP)
        if (hex(sha3_256(wrapped)) != line.str("w")) throw CryptoFail("wrapped key doesn't match the signed header")
        val key = unwrapKey(wrapped, pre.kemPq, pre.kemPqPk, pre.kemEc, pre.kemEcPk, wrapAadV2(room, itemEpoch, me.user, myFp, myDev, pid))
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
