package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Canonical JSON, byte-identical to the web chat's canon() (crypto.js): keys sorted at every level, no spaces, strings
 * escaped exactly like JavaScript's JSON.stringify, and only whole numbers within JavaScript's safe-integer range.
 * Everything signed is canonical bytes sent as base64, so the bytes that were signed are the bytes that get verified.
 */
object Canon {
    private const val MAX_SAFE = 9007199254740991L

    fun encode(v: JsonElement): String = StringBuilder().also { write(it, v) }.toString()

    fun bytes(v: JsonElement): ByteArray = utf8(encode(v))

    private fun write(sb: StringBuilder, v: JsonElement) {
        when (v) {
            is JsonNull -> sb.append("null")
            is JsonPrimitive -> when {
                v.isString -> string(sb, v.content)
                v.content == "true" || v.content == "false" -> sb.append(v.content)
                else -> {
                    val n = v.content.toLongOrNull()
                    if (n == null || n > MAX_SAFE || n < -MAX_SAFE || v.content != n.toString()) throw CryptoFail("only whole numbers are signed")
                    sb.append(n)
                }
            }
            is JsonArray -> { sb.append('['); v.forEachIndexed { i, e -> if (i > 0) sb.append(','); write(sb, e) }; sb.append(']') }
            is JsonObject -> {
                sb.append('{')
                // JavaScript sorts keys by UTF-16 code units, which is what String.compareTo does
                v.keys.sorted().forEachIndexed { i, k -> if (i > 0) sb.append(','); string(sb, k); sb.append(':'); write(sb, v.getValue(k)) }
                sb.append('}')
            }
        }
    }

    /** JSON.stringify's string escaping (ES2019 well-formed): \" \\ \b \f \n \r \t, other controls and lone surrogates as \u00xx. */
    private fun string(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000c' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append("\\u%04x".format(c.code))
                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> { sb.append(c).append(s[i + 1]); i++ }
                c.isSurrogate() -> sb.append("\\u%04x".format(c.code))
                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }

    private val strict = Json { isLenient = false }

    /** A signed header: base64 of canonical JSON, version 1. Refuses anything that isn't exactly canonical. */
    fun parseSigned(b64str: String, maxLen: Int): Signed {
        val raw = unb64(b64str)
        if (raw.size > maxLen) throw CryptoFail("too large")
        val text = try { Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(raw)).toString() }
                   catch (e: Exception) { throw CryptoFail("malformed header") }
        val obj = try { strict.parseToJsonElement(text) } catch (e: Exception) { throw CryptoFail("malformed header") }
        if (obj !is JsonObject || (obj["v"] as? JsonPrimitive)?.intOrNull != 1) throw CryptoFail("unsupported version")
        if (encode(obj) != text) throw CryptoFail("header is not canonical")
        return Signed(raw, obj)
    }

    class Signed(val raw: ByteArray, val obj: JsonObject)
}

// Small typed getters for signed headers (a missing or wrong-typed field is a protocol refusal, never a crash).
fun JsonObject.str(k: String): String = (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw CryptoFail("missing $k")
fun JsonObject.strOrNull(k: String): String? = (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content
fun JsonObject.long(k: String): Long = (this[k] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: throw CryptoFail("missing $k")
fun JsonObject.longOrNull(k: String): Long? = (this[k] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
fun JsonObject.arr(k: String): JsonArray = this[k] as? JsonArray ?: throw CryptoFail("missing $k")
