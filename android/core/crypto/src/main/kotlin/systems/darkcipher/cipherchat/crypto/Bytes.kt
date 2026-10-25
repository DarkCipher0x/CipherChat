package systems.darkcipher.cipherchat.crypto

import java.security.SecureRandom
import java.util.Base64

/** Any refusal by the protocol: bad signature, wrong key, tampered data, malformed input. Never leaks key material. */
class CryptoFail(message: String) : Exception(message)

internal val rng = SecureRandom()

fun random(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var o = 0
    for (p in parts) { p.copyInto(out, o); o += p.size }
    return out
}

fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

private val B64_RE = Regex("^[A-Za-z0-9+/]*={0,2}$")

/** Strict standard base64 with padding, exactly like the web chat's unb64(); [size] checks the decoded length. */
fun unb64(s: String, size: Int? = null): ByteArray {
    if (s.length % 4 != 0 || !B64_RE.matches(s)) throw CryptoFail("malformed base64")
    val out = try { Base64.getDecoder().decode(s) } catch (e: IllegalArgumentException) { throw CryptoFail("malformed base64") }
    if (size != null && out.size != size) throw CryptoFail("wrong length")
    return out
}

fun hex(b: ByteArray): String = buildString(b.size * 2) { for (x in b) append("%02x".format(x.toInt() and 0xff)) }

fun fromHex(h: String): ByteArray {
    require(h.length % 2 == 0 && h.all { it in "0123456789abcdefABCDEF" }) { "not hex" }
    return ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

internal fun u32be(n: Int) = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

fun wipe(vararg arrays: ByteArray?) { for (a in arrays) a?.fill(0) }

/** Constant-time comparison. */
fun sameBytes(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var d = 0
    for (i in a.indices) d = d or (a[i].toInt() xor b[i].toInt())
    return d == 0
}

/** URL-safe base64 without padding (message ids). */
internal fun b64url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
