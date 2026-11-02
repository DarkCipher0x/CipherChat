package systems.darkcipher.cipherchat.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Seals the chat's key store file (room keys this phone kept, PROTOCOL.md §10) with a second hardware key. Unlike the
 * vault's key it needs no fingerprint per use, because the keys inside are already sealed twice by the chat (the device
 * key and the person's master secret), and history arriving in the background mustn't wait for a prompt. It can't be
 * exported and only works while the phone is unlocked, so a copy of the app's files opens nothing elsewhere.
 * File format: iv (12) ‖ AES-256-GCM ciphertext.
 */
object StoreSeal {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "cipherchat.keystore"
    private const val TAG_BITS = 128
    private const val IV = 12

    private fun store() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun key(): SecretKey {
        val s = store()
        (s.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUnlockedDeviceRequired(true)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply { init(spec) }.generateKey()
    }

    fun protect(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val ct = c.doFinal(plain)
        return c.iv + ct
    }

    fun unprotect(sealed: ByteArray): ByteArray {
        require(sealed.size > IV + TAG_BITS / 8) { "damaged key store" }
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, sealed, 0, IV)) }
        return c.doFinal(sealed, IV, sealed.size - IV)
    }

    /** Forgets the key (every key store on this phone becomes unreadable and is made again on the next unlock). */
    fun delete() { val s = store(); if (s.containsAlias(ALIAS)) s.deleteEntry(ALIAS) }
}
