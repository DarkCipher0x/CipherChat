package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.Call
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import java.util.concurrent.CopyOnWriteArrayList

/** An incoming call, already verified (signed by a trusted identity, fresh). */
data class IncomingCall(val call: String, val room: String, val from: String, val media: String, val people: List<String>)

interface CallListener {
    fun ringing(call: IncomingCall) {}
    /** (call id, why): answered elsewhere, missed, the caller hung up... */
    fun ringStopped(call: String, why: String) {}
    /** Signals for the active call, to pass to the call screen as they come. */
    fun signals(items: JsonArray) {}
}

/**
 * Calls for the phone (docs/CALLS.md; the Windows app's Calls). The call itself (WebRTC, frame encryption, the call
 * screen) runs in a WebView from the same JavaScript as the web portal; this class is everything it may ask of the
 * app, so the identity's private keys stay here: seal / open signals, wrap / unwrap sender keys, the call words, and
 * "calls/signal" / "calls/turn" over this app's PQ-only TLS connection. Ringing is native (no WebView runs until a call
 * is answered), and every signal of a ringing or active call is kept so the call screen can be given them when it opens.
 */
class Calls internal constructor(private val e: ChatEngine) {
    private val seenNative = HashSet<String>()
    private val seenWindow = HashSet<String>()
    private val lock = Any()
    private class Kept(val at: Long, val item: JsonObject)
    private val byCall = HashMap<String, MutableList<Kept>>()
    private val ringing = HashMap<String, IncomingCall>()
    @Volatile private var active: String? = null                            // the call the screen is showing
    private val listeners = CopyOnWriteArrayList<CallListener>()

    /** This app instance's device id in calls. */
    val device: String = Call.newDeviceId()

    fun addListener(l: CallListener) = listeners.add(l)
    fun removeListener(l: CallListener) = listeners.remove(l)
    private inline fun emit(f: (CallListener) -> Unit) { for (l in listeners) try { f(l) } catch (x: RuntimeException) { } }

    val trustedUsers: List<String> get() = e.people.values.filter { it.trust == TrustLevel.OK && it.pub != null }.map { it.user }
    val activeCall: String? get() = active

    // ------------------------------------------------------------------------------------------- from the poll
    internal fun onSignals(items: JsonArray) {
        val forScreen = ArrayList<JsonObject>()
        val now = System.currentTimeMillis()
        for (it in items.filterIsInstance<JsonObject>()) {
            val call = it.strOrNull("call") ?: continue
            val mineToShow = synchronized(lock) {
                byCall.getOrPut(call) { ArrayList() }.add(Kept(now, it))
                for (k in byCall.keys.toList()) {
                    val l = byCall[k]!!
                    l.removeAll { x -> now - x.at > KEEP_MS }
                    if (l.isEmpty() && k != active) byCall.remove(k)
                }
                call == active
            }
            if (mineToShow) forScreen.add(it) else native(it)
        }
        if (forScreen.isNotEmpty()) { val a = JsonArray(forScreen); emit { it.signals(a) } }
    }

    private fun native(it: JsonObject) {
        val h = try { synchronized(seenNative) { Call.open(it, { u -> e.trusted(u)?.pub }, seenNative) } } catch (x: CryptoFail) { return }   // unverifiable: ignored
        val call = h.str("call")
        val kind = h.str("kind")
        val mine = h.str("from") == e.myUser
        when {
            kind == "ring" && !mine -> {
                if (active != null) { e.scope.launch { sendBusy(h) }; return }
                val people = (h["people"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }?.take(8) ?: emptyList()
                val inc = IncomingCall(call, h.str("room"), h.str("from"), if (h.strOrNull("media") == "video") "video" else "audio", people)
                synchronized(lock) { if (ringing.containsKey(call)) return; ringing[call] = inc }
                emit { l -> l.ringing(inc) }
                e.scope.launch { delay(RING_MS); stopRing(call, "missed") }
            }
            kind == "accept" && mine -> stopRing(call, "answered on another device")
            kind == "decline" && mine -> stopRing(call, "declined on another device")
            kind == "end" && !mine -> stopRing(call, "missed")
        }
    }

    private fun stopRing(call: String, why: String) {
        synchronized(lock) { if (ringing.remove(call) == null) return }
        emit { it.ringStopped(call, why) }
    }

    private suspend fun reply(kind: String, room: String, call: String, to: String) {
        try {
            val toArr = buildJsonArray { add(JsonPrimitive(to)) }
            val sig = seal(buildJsonObject { put("kind", kind); put("room", room); put("call", call); put("dev", device); put("to", toArr) })
            signal(buildJsonObject { put("room", room); put("to", toArr); put("sig", sig) })
        } catch (x: ApiException) { } catch (x: CryptoFail) { }
    }

    private suspend fun sendBusy(ring: JsonObject) = reply("busy", ring.str("room"), ring.str("call"), ring.str("from"))

    // ------------------------------------------------------------------------------------------- the call screen
    /** The screen opens a call: it gets every signal kept for it so far (the ring, early ICE...) and all that follow. */
    fun open(call: String): JsonArray {
        val (items, wasRinging) = synchronized(lock) {
            active = call
            val r = ringing.remove(call) != null
            synchronized(seenWindow) { seenWindow.clear() }
            JsonArray(byCall[call]?.map { it.item } ?: emptyList()) to r
        }
        if (wasRinging) emit { it.ringStopped(call, "answered") }       // the ring notification goes
        return items
    }

    /** A call that is ringing here right now (for answering or declining from a notification). */
    fun ringingCall(call: String): IncomingCall? = synchronized(lock) { ringing[call] }

    /** A call the screen starts: from now on its signals go to the screen. */
    fun started(call: String) = synchronized(lock) {
        if (active != call) { active = call; synchronized(seenWindow) { seenWindow.clear() } }
    }

    fun closed() = synchronized(lock) { active = null }

    fun decline(inc: IncomingCall) {
        stopRing(inc.call, "declined")
        e.scope.launch { reply("decline", inc.room, inc.call, inc.from) }
    }

    // ------------------------------------------------------------------------------------------- what the screen may ask
    fun seal(fields: JsonObject): JsonObject {
        if (fields.strOrNull("dev") != device) throw CryptoFail("a call signal must carry this device's id")
        return Call.seal(e.me.id, e.me.fp, fields)
    }

    fun openSignal(item: JsonObject): JsonObject = synchronized(seenWindow) { Call.open(item, { u -> e.trusted(u)?.pub }, seenWindow) }

    fun wrapKey(key32: ByteArray, call: String, epoch: Long, users: List<String>): JsonObject {
        val people = users.map { u -> e.trusted(u)?.pub ?: throw CryptoFail("$u isn't verified") }
        return Call.wrapSenderKey(key32, call, e.me.id, device, epoch, people)
    }

    fun unwrapKey(sig: JsonObject): ByteArray = Call.unwrapSenderKey(sig, e.me.id, e.me.fp)

    fun words(call: String, users: List<String>): List<String> =
        Call.callWords(call, users.map { u -> u to (if (u == e.myUser) e.me.fp else e.trusted(u)?.fp ?: throw CryptoFail("$u isn't verified")) })

    suspend fun signal(body: JsonObject): JsonObject = e.api.call("calls/signal", body)

    suspend fun turn(): JsonObject = e.api.call("calls/turn")

    companion object {
        private const val KEEP_MS = 120_000L
        private const val RING_MS = 45_000L
    }
}
