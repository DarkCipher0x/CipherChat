package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.text.Normalizer

/**
 * The sealed identity backup on the server, identical to the web chat's: AES-256-GCM under
 * HKDF-SHA-512(Argon2id(passphrase) || server key share). Argon2id: 64 MiB, 3 passes, 1 lane, version 0x13.
 * The same passphrase opens it in a browser and on the phone.
 */
object Backup {
    const val M_KIB = 65536; const val T = 3; const val P = 1

    fun seal(user: String, passphrase: CharArray, pepper: ByteArray, pepperVer: Int, payload: JsonObject): JsonObject {
        val salt = random(32)
        val key = key(user, passphrase, pepper, pepperVer, salt, M_KIB, T, P)
        try {
            val sealed = aesSeal(key, Canon.bytes(payload), utf8("dcx-chat/v1/backup|$user|$pepperVer"))
            return buildJsonObject {
                put("v", 1)
                put("kdf", buildJsonObject { put("alg", "argon2id"); put("m", M_KIB); put("t", T); put("p", P); put("salt", b64(salt)) })
                put("pepper_ver", pepperVer)
                put("n", b64(sealed.copyOfRange(0, 12)))
                put("c", b64(sealed.copyOfRange(12, sealed.size)))
            }
        } finally { wipe(key) }
    }

    fun open(user: String, passphrase: CharArray, pepper: ByteArray, backup: JsonObject): JsonObject {
        val kdf = backup["kdf"] as? JsonObject ?: throw CryptoFail("unsupported backup format")
        val m = kdf.longOrNull("m"); val t = kdf.longOrNull("t"); val p = kdf.longOrNull("p")
        if (backup.longOrNull("v") != 1L || kdf.strOrNull("alg") != "argon2id" || m == null || t == null || p == null ||
            m !in 65536..1048576 || t !in 2..16 || p !in 1..4) throw CryptoFail("unsupported backup format")
        val ver = backup.long("pepper_ver").toInt()
        val key = key(user, passphrase, pepper, ver, unb64(kdf.str("salt"), 32), m.toInt(), t.toInt(), p.toInt())
        try {
            val plain = try {
                aesOpen(key, concat(unb64(backup.str("n"), 12), unb64(backup.str("c"))), utf8("dcx-chat/v1/backup|$user|$ver"))
            } catch (e: CryptoFail) { throw CryptoFail("wrong passphrase") }
            try { return Json.parseToJsonElement(String(plain, Charsets.UTF_8)) as JsonObject } finally { wipe(plain) }
        } finally { wipe(key) }
    }

    private fun key(user: String, passphrase: CharArray, pepper: ByteArray, pepperVer: Int, salt: ByteArray, m: Int, t: Int, p: Int): ByteArray {
        // NFKC like String.prototype.normalize("NFKC") in the browser, then UTF-8
        val pw = utf8(Normalizer.normalize(String(passphrase), Normalizer.Form.NFKC))
        val a = ByteArray(32)
        try {
            val g = Argon2BytesGenerator()
            g.init(Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(m).withIterations(t).withParallelism(p).withSalt(salt).build())
            g.generateBytes(pw, a)
            val ikm = concat(a, pepper)
            try { return hkdf32(ikm, salt, "dcx-chat/v1/backup-key|$user|$pepperVer") } finally { wipe(ikm) }
        } finally { wipe(pw, a) }
    }
}
