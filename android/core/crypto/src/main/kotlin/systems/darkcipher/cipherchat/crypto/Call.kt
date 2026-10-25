package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The cryptography of calls, line for line the same as web/app/callcrypto.js and Windows' Call.cs (docs/CALLS.md):
 * signed call signals, per-sender media keys wrapped with ML-KEM-1024 + X25519, and the call words. The Android call
 * screen (a WebView running the shared call core) asks for these through its bridge, so the identity's private keys
 * stay in this process and never enter the WebView.
 */
object Call {
    const val SIGNAL_LABEL = "dcx-chat/v1/call-signal"
    const val SIGNAL_MAX = 48 * 1024
    private const val FRESH_MS = 120_000L
    private val KINDS = setOf("ring", "accept", "decline", "busy", "offer", "answer", "ice", "key", "leave", "end", "state")
    private val ID = Regex("^[A-Za-z0-9_-]{22}$")
    private val DEV = Regex("^[A-Za-z0-9_-]{8,22}$")

    fun newCallId(): String = b64url(random(16))
    fun newDeviceId(): String = b64url(random(12))

    /** fields: kind, room, call, dev, to and the kind's own fields. Returns the {h, s} the server relays. */
    fun seal(me: Identity, myFp: String, fields: JsonObject, now: Long = System.currentTimeMillis()): JsonObject {
        val hdr = JsonObject(buildJsonObject {
            put("v", 1); put("t", "call"); put("from", me.user); put("from_fp", myFp); put("at", now); put("n", b64url(random(9)))
        } + fields)
        val raw = Canon.bytes(hdr)
        if (raw.size > SIGNAL_MAX) throw CryptoFail("call signal too large")
        return buildJsonObject { put("h", b64(raw)); put("s", b64(sign(me, SIGNAL_LABEL, raw))) }
    }

    /** One entry of poll().signals -> the verified header. [trusted] is the identity this device trusts, or null. */
    fun open(item: JsonObject, trusted: (String) -> PublicIdentity?, seen: MutableSet<String>, now: Long = System.currentTimeMillis()): JsonObject {
        val sig = item["sig"] as? JsonObject ?: throw CryptoFail("missing sig")
        val signed = Canon.parseSigned(sig.str("h"), SIGNAL_MAX)
        val o = signed.obj
        if (o.strOrNull("t") != "call" || o.strOrNull("from") != item.strOrNull("from") || o.strOrNull("room") != item.strOrNull("room") ||
            o.strOrNull("kind") != item.strOrNull("kind") || o.strOrNull("call") != item.strOrNull("call"))
            throw CryptoFail("call signal doesn't match its envelope")
        if (o.str("kind") !in KINDS || !ID.matches(o.str("call")) || !DEV.matches(o.strOrNull("dev") ?: "") || o["to"] !is JsonArray)
            throw CryptoFail("malformed call signal")
        if (kotlin.math.abs(now - o.long("at")) > FRESH_MS) throw CryptoFail("call signal is stale")
        val who = trusted(o.str("from"))
        if (who == null || who.fp != o.strOrNull("from_fp")) throw CryptoFail("call signal from an identity you don't trust")
        if (!verify(who, SIGNAL_LABEL, signed.raw, unb64(sig.str("s")))) throw CryptoFail("call signal signature is invalid")
        val tag = o.str("call") + "|" + o.str("dev") + "|" + o.str("n")
        synchronized(seen) {
            if (!seen.add(tag)) throw CryptoFail("replayed call signal")
            if (seen.size > 5000) seen.remove(seen.first())
        }
        return o
    }

    private fun keyAad(call: String, from: String, dev: String, epoch: Long, to: String, toFp: String) =
        utf8(listOf("dcx-chat/v1/call-key", call, from, dev, epoch.toString(), to, toFp).joinToString("|"))

    /** The fields of a "key" signal: this device's sender key for an epoch, wrapped to each recipient. */
    fun wrapSenderKey(key32: ByteArray, call: String, me: Identity, dev: String, epoch: Long, recipients: List<PublicIdentity>): JsonObject =
        buildJsonObject {
            put("epoch", epoch)
            put("keys", buildJsonObject {
                for (r in recipients) put(r.user, b64(wrapKey(key32, r.kemPq, r.kemEc, keyAad(call, me.user, dev, epoch, r.user, r.fp))))
            })
        }

    fun unwrapSenderKey(sig: JsonObject, me: Identity, myFp: String): ByteArray {
        val w = (sig["keys"] as? JsonObject)?.strOrNull(me.user)
        val epoch = sig.longOrNull("epoch")
        if (w == null || epoch == null || epoch < 0) throw CryptoFail("no call key for you in this signal")
        return unwrapKey(unb64(w), me, keyAad(sig.str("call"), sig.str("from"), sig.str("dev"), epoch, me.user, myFp))
    }

    private val WORDS = ("acorn agent alpha amber anchor angel apple arrow atlas autumn badge baker bamboo banjo barrel basin beacon " +
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
        "tundra turtle umbrella valley velvet violet volcano wagon walnut walrus willow window winter wizard yacht yarrow zebra zephyr zinc").split(" ")

    /** Four words from the call id and every participant's identity: the same on every screen only if nobody is in the middle. */
    fun callWords(call: String, participants: List<Pair<String, String>>): List<String> {
        if (WORDS.size != 256 || WORDS.toSet().size != 256) throw CryptoFail("call word list must be 256 distinct words")
        val lines = participants.map { it.first + ":" + it.second }.sorted()
        val h = sha3_256(utf8((listOf("dcx-chat/v1/call-words", call) + lines).joinToString("|")))
        return listOf(WORDS[h[0].toInt() and 0xff], WORDS[h[1].toInt() and 0xff], WORDS[h[2].toInt() and 0xff], WORDS[h[3].toInt() and 0xff])
    }
}
