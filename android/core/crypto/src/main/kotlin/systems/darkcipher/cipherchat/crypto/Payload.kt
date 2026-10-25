package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Message payload kinds (inside the encrypted, signed message), checked exactly like the web chat's checkPayload()
 * and Windows' Payload.cs:
 *   text {text, re?}   me {text}   file {text (caption), files: [...], re?}
 *   react {text: "", target: <msg id>, emoji, on}   edit {text, target}
 *   text/me/file may carry burn: seconds visible once opened (10-300)
 * Unknown kinds or malformed fields are refused, so no client ever shows half a message.
 */
object Payload {
    private val ID = Regex("^[A-Za-z0-9_-]{22}$")
    private val BLOB = Regex("^[0-9a-f]{24}$")
    private val SHA3 = Regex("^[0-9a-f]{64}$")
    private val KEY = Regex("^[A-Za-z0-9+/]{43}=$")

    private fun bad() = CryptoFail("malformed message")
    private fun str(e: JsonElement?): String? = (e as? JsonPrimitive)?.takeIf { it.isString }?.content
    private fun int(e: JsonElement?): Long? = (e as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { kotlin.math.abs(it) <= 9007199254740991L }
    private fun isId(e: JsonElement?) = str(e)?.let { ID.matches(it) } == true

    fun check(p: JsonObject): JsonObject {
        val kind = if (p.containsKey("k")) str(p["k"]) ?: throw bad() else "text"
        if (p.containsKey("re") && !isId(p["re"])) throw bad()
        if (p.containsKey("burn")) {
            val b = int(p["burn"])
            if (b == null || b < 10 || b > 300 || kind !in setOf("text", "me", "file")) throw bad()
        }
        when (kind) {
            "text", "me" -> return p
            "react" -> {
                val emoji = str(p["emoji"])
                val on = (p["on"] as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull
                if (!isId(p["target"]) || emoji == null || emoji.length !in 1..16 || on == null) throw bad()
                return p
            }
            "edit" -> { if (!isId(p["target"])) throw bad(); return p }
            "file" -> {
                val files = p["files"] as? JsonArray ?: throw bad()
                if (files.size !in 1..10) throw bad()
                for (f in files) checkFile(f as? JsonObject ?: throw bad())
                return p
            }
            else -> throw bad()
        }
    }

    private fun ref(r: JsonObject?): Boolean {
        if (r == null) return false
        val size = int(r["size"]) ?: return false
        return str(r["blob"])?.let { BLOB.matches(it) } == true && str(r["sha3"])?.let { SHA3.matches(it) } == true &&
            str(r["key"])?.let { KEY.matches(it) } == true && size >= 0 && size <= Files.MAX
    }

    private fun checkFile(f: JsonObject) {
        if (!ref(f) || (str(f["name"])?.length ?: 999) > 200 || (str(f["mime"])?.length ?: 999) > 100 ||
            str(f["kind"]) !in setOf("image", "video", "audio", "file")) throw bad()
        if (f.containsKey("thumb") && !ref(f["thumb"] as? JsonObject)) throw bad()
        for (k in listOf("w", "h", "dur")) if (f.containsKey(k) && int(f[k])?.let { it in 0 until 10_000_000 } != true) throw bad()
    }
}
