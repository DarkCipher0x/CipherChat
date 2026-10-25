package systems.darkcipher.cipherchat.crypto

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Attachments (files, pictures, videos, GIFs), byte-compatible with the web chat's sealFile/openFile and Windows'
 * Files.cs: a fresh random AES-256 key per file (sent inside the signed, encrypted message), the plaintext zero-padded
 * to whole 64 KiB chunks (the server sees only the size in 64 KiB steps), each chunk AES-256-GCM with nonce = chunk
 * index and "index|last" as associated data, so chunks can't be reordered, dropped or swapped between files. The
 * SHA3-256 of the whole ciphertext also goes in the signed message.
 */
object Files {
    const val CHUNK = 65536
    const val SEALED_CHUNK = CHUNK + 16
    const val MAX = 1600L * CHUNK                              // 100 MiB, the server's limit

    class Sealed(val key: String, val data: ByteArray, val sha3: String, val size: Long)

    // 12-byte nonce, chunk index big-endian in bytes 4..7 (the web chat: DataView.setUint32(4, i))
    private fun nonce(i: Int) = ByteArray(12).also { it[4] = (i ushr 24).toByte(); it[5] = (i ushr 16).toByte(); it[6] = (i ushr 8).toByte(); it[7] = i.toByte() }
    private fun aad(i: Int, last: Boolean) = utf8("dcx-chat/v1/file|$i|${if (last) 1 else 0}")

    fun seal(bytes: ByteArray): Sealed {
        if (bytes.size > MAX) throw CryptoFail("file too large")
        val key = random(32)
        val chunks = maxOf(1, (bytes.size + CHUNK - 1) / CHUNK)
        val out = ByteArray(chunks * SEALED_CHUNK)
        val spec = SecretKeySpec(key, "AES")
        val plain = ByteArray(CHUNK)
        try {
            for (i in 0 until chunks) {
                plain.fill(0)
                val start = i * CHUNK
                val n = minOf(CHUNK, maxOf(0, bytes.size - start))
                if (n > 0) System.arraycopy(bytes, start, plain, 0, n)
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.ENCRYPT_MODE, spec, GCMParameterSpec(128, nonce(i)))
                c.updateAAD(aad(i, i == chunks - 1))
                c.doFinal(plain, 0, CHUNK, out, i * SEALED_CHUNK)
            }
            return Sealed(b64(key), out, hex(sha3_256(out)), bytes.size.toLong())
        } finally { wipe(plain, key) }
    }

    fun open(sealed: ByteArray, keyB64: String, size: Long, sha3Hex: String): ByteArray {
        if (sealed.isEmpty() || sealed.size % SEALED_CHUNK != 0) throw CryptoFail("not an encrypted attachment")
        if (hex(sha3_256(sealed)) != sha3Hex) throw CryptoFail("the attachment doesn't match its signed hash")
        val chunks = sealed.size / SEALED_CHUNK
        // the padding never adds a whole extra chunk: only the last chunk is partly zeros (a 0-byte file is one chunk)
        if (size < 0 || size > chunks.toLong() * CHUNK || (chunks > 1 && size <= (chunks - 1).toLong() * CHUNK)) throw CryptoFail("attachment size doesn't match")
        val key = unb64(keyB64, 32)
        val out = ByteArray(chunks * CHUNK)
        try {
            val spec = SecretKeySpec(key, "AES")
            for (i in 0 until chunks) {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE, spec, GCMParameterSpec(128, nonce(i)))
                c.updateAAD(aad(i, i == chunks - 1))
                try { c.doFinal(sealed, i * SEALED_CHUNK, SEALED_CHUNK, out, i * CHUNK) }
                catch (e: AEADBadTagException) { throw CryptoFail("attachment decryption failed (it was changed)") }
            }
            return out.copyOf(size.toInt())
        } finally { wipe(key) }
    }

    /** What a picture or video really is, from its first bytes (never from the name or the sender's label). */
    fun sniff(b: ByteArray): String {
        fun at(o: Int, vararg v: Int) = b.size >= o + v.size && v.indices.all { b[o + it] == v[it].toByte() }
        if (at(0, 0x89, 0x50, 0x4e, 0x47)) return "image/png"
        if (at(0, 0xff, 0xd8, 0xff)) return "image/jpeg"
        if (at(0, 0x47, 0x49, 0x46, 0x38)) return "image/gif"
        if (at(0, 0x52, 0x49, 0x46, 0x46) && at(8, 0x57, 0x45, 0x42, 0x50)) return "image/webp"
        if (at(4, 0x66, 0x74, 0x79, 0x70) && b.size >= 12) {
            when (String(b, 8, 4, Charsets.US_ASCII)) {
                "avif", "avis" -> return "image/avif"
                "isom", "iso2", "mp41", "mp42", "avc1", "M4V ", "dash" -> return "video/mp4"
                "qt  " -> return "video/quicktime"
            }
        }
        if (at(0, 0x1a, 0x45, 0xdf, 0xa3)) return "video/webm"
        return "application/octet-stream"
    }
}
