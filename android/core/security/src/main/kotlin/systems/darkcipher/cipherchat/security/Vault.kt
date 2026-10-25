package systems.darkcipher.cipherchat.security

import androidx.fragment.app.FragmentActivity
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * What this phone remembers (its pairings), sealed twice over:
 *   vault.key = iv(12) | AES-256-GCM(data key) under the [Keystore] key: opening it takes a fingerprint or the screen lock.
 *   vault.bin = "CCA1" | iv(12) | AES-256-GCM(contents) under the data key, which stays in memory only while the app
 *               is unlocked, so saving needs no second prompt.
 * A copied data folder is useless without this phone's secure hardware and its owner. The vault never holds the chat
 * passphrase or any chat key: those exist only in memory between unlocking and locking the chat.
 */
class Vault(dir: File) {
    private val keyFile = File(dir, "vault.key")
    private val dataFile = File(dir, "vault.bin")
    private var dataKey: ByteArray? = null

    val exists: Boolean get() = keyFile.exists() && Keystore.exists()
    val open: Boolean get() = dataKey != null

    class Invalidated : Exception("The phone's security changed (a new fingerprint or screen lock), so the saved pairings can't be opened. Pair this phone again.")

    /** Opens (or on first use creates) the vault after one prompt. Returns its contents (empty the first time). */
    suspend fun unlock(activity: FragmentActivity): ByteArray {
        if (!exists) {
            forget()
            Keystore.ensure(Biometric.strongBox(activity))
            val key = ByteArray(32).also { rng.nextBytes(it) }
            val c = Biometric.authenticate(activity, Keystore.encryptCipher() ?: throw Invalidated(), "Set up CipherChat", "Protects the servers this phone is paired with")
            atomicWrite(keyFile, c.iv + c.doFinal(key))
            dataKey = key
            return ByteArray(0)
        }
        val blob = keyFile.readBytes()
        require(blob.size == 12 + 32 + 16) { "the vault key file is damaged" }
        val cipher = Keystore.decryptCipher(blob.copyOfRange(0, 12)) ?: run { forget(); throw Invalidated() }
        val c = Biometric.authenticate(activity, cipher, "Unlock CipherChat", "Confirm it's you")
        dataKey = c.doFinal(blob.copyOfRange(12, blob.size))
        return read()
    }

    private fun read(): ByteArray {
        if (!dataFile.exists()) return ByteArray(0)
        val b = dataFile.readBytes()
        require(b.size > 4 + 12 + 16 && String(b, 0, 4, Charsets.US_ASCII) == MAGIC) { "the vault file is damaged" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(dataKey!!, "AES"), GCMParameterSpec(128, b, 4, 12))
        c.updateAAD(AAD)
        return c.doFinal(b, 16, b.size - 16)
    }

    /** Seals [contents] (the app's JSON) under the in-memory data key. The vault must be open. */
    fun save(contents: ByteArray) {
        val k = dataKey ?: throw IllegalStateException("the vault is locked")
        val iv = ByteArray(12).also { rng.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, iv))
        c.updateAAD(AAD)
        atomicWrite(dataFile, MAGIC.toByteArray(Charsets.US_ASCII) + iv + c.doFinal(contents))
    }

    /** Wipes the data key from memory (the files stay). */
    fun lock() { dataKey?.fill(0); dataKey = null }

    /** Forgets every pairing on this phone: the files and the hardware key. */
    fun forget() {
        lock()
        keyFile.delete(); dataFile.delete()
        Keystore.delete()
    }

    private fun atomicWrite(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeBytes(bytes)
        check(tmp.renameTo(target)) { "couldn't save ${target.name}" }
    }

    companion object {
        private const val MAGIC = "CCA1"
        private val AAD = "cipherchat/android/vault/v1".toByteArray()
        private val rng = SecureRandom()
    }
}
