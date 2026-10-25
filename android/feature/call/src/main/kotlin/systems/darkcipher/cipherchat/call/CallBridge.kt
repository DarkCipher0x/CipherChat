package systems.darkcipher.cipherchat.call

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.client.ApiException
import systems.darkcipher.cipherchat.client.ChatEngine
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.b64
import systems.darkcipher.cipherchat.crypto.long
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.unb64
import systems.darkcipher.cipherchat.crypto.wipe

/**
 * What the call page may ask of the app (the Windows CallWindow's Dispatch, op for op). Anything else is refused.
 * The app sets [engine] while the chat is unlocked; [inCall] keeps auto-lock away during a call.
 */
object CallBridge {
    @Volatile var engine: ChatEngine? = null
    @Volatile var inCall = false
    /** Release builds: no WebView debugging, no development extras. */
    @Volatile var secure = true

    class Refused(message: String) : Exception(message)

    private fun obj(e: JsonElement?) = e as? JsonObject ?: throw Refused("malformed request")
    private fun users(a: JsonObject) = (a["users"] as? JsonArray ?: throw Refused("malformed request"))
        .map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw Refused("malformed request") }

    suspend fun dispatch(e: ChatEngine, op: String, args: JsonElement?): JsonElement {
        val c = e.calls
        return when (op) {
            "seal" -> {
                val fields = obj(args)
                c.started(fields.str("call"))                       // a call this screen started: its signals come here from now on
                c.seal(fields)
            }
            "open" -> c.openSignal(obj(args))
            "wrapKey" -> {
                val a = obj(args)
                val key = unb64(a.str("key"), 32)
                try { c.wrapKey(key, a.str("call"), a.long("epoch"), users(a)) } finally { wipe(key) }
            }
            "unwrapKey" -> {
                val key = c.unwrapKey(obj(args))
                try { JsonPrimitive(b64(key)) } finally { wipe(key) }
            }
            "words" -> { val a = obj(args); buildJsonArray { c.words(a.str("call"), users(a)).forEach { add(JsonPrimitive(it)) } } }
            "api" -> {
                val a = obj(args)
                when (a.strOrNull("path")) {
                    "calls/signal" -> c.signal(obj(a["body"]))
                    "calls/turn" -> c.turn()
                    else -> throw Refused("the call page may only send call signals")
                }
            }
            else -> throw Refused("unknown request")
        }
    }

    /** One request from the page -> its reply. */
    suspend fun answer(e: ChatEngine, m: JsonObject): JsonObject {
        val id = m["id"] ?: return JsonObject(emptyMap())
        return try {
            buildJsonObject { put("reply", id); put("ok", true); put("value", dispatch(e, m.strOrNull("op") ?: "", m["args"])) }
        } catch (x: Exception) {
            if (x !is CryptoFail && x !is ApiException && x !is Refused && x !is IllegalStateException && x !is IllegalArgumentException) throw x
            buildJsonObject { put("reply", id); put("ok", false); put("error", x.message ?: "refused") }
        }
    }
}
