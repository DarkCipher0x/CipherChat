package systems.darkcipher.cipherchat.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The hardware key that wraps the vault's data key (DarkCipher Command's design). It lives in StrongBox where the
 * phone has one (a separate secure chip), otherwise in the TEE; it can't be exported, and every single use needs a
 * fresh Class 3 fingerprint or the screen lock (PIN, pattern, password). Enrolling a new fingerprint destroys it, so
 * someone who adds their finger to an unlocked phone can't open the vault.
 */
object Keystore {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "cipherchat.vault"
    private const val TAG_BITS = 128

    private fun store() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun exists(): Boolean = store().containsAlias(ALIAS)

    /** Creates the key if it's missing. [strongBox] = put it in the secure element (fails on phones without one). */
    fun ensure(strongBox: Boolean) {
        if (exists()) return
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply { init(spec); generateKey() }
    }

    fun delete() { if (exists()) store().deleteEntry(ALIAS) }

    private fun key(): SecretKey = (store().getEntry(ALIAS, null) as KeyStore.SecretKeyEntry).secretKey

    /** An ENCRYPT cipher for the prompt to authorise. Null if the key was invalidated (new fingerprint, lock removed). */
    fun encryptCipher(): Cipher? = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
    } catch (e: KeyPermanentlyInvalidatedException) { null }

    fun decryptCipher(iv: ByteArray): Cipher? = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, iv)) }
    } catch (e: KeyPermanentlyInvalidatedException) { null }
}
