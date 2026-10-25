package systems.darkcipher.cipherchat.security

import android.content.Context
import android.content.pm.PackageManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * AndroidX BiometricPrompt, always with a CryptoObject: the authentication unlocks one cryptographic operation in
 * the secure hardware, never just an "it was them" boolean. Class 3 fingerprint or face, or the screen lock.
 */
object Biometric {
    const val ALLOWED = BIOMETRIC_STRONG or DEVICE_CREDENTIAL

    fun strongBox(context: Context) = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    enum class Readiness { Ready, NoScreenLock, Unavailable }

    fun readiness(context: Context): Readiness = when (BiometricManager.from(context).canAuthenticate(ALLOWED)) {
        BiometricManager.BIOMETRIC_SUCCESS -> Readiness.Ready
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Readiness.NoScreenLock
        else -> Readiness.Unavailable
    }

    class AuthError(val code: Int, message: String) : Exception(message) {
        val cancelled get() = code == BiometricPrompt.ERROR_USER_CANCELED || code == BiometricPrompt.ERROR_NEGATIVE_BUTTON || code == BiometricPrompt.ERROR_CANCELED
    }

    /** Shows the prompt; returns the authorised cipher. */
    suspend fun authenticate(activity: FragmentActivity, cipher: Cipher, title: String, subtitle: String): Cipher =
        suspendCancellableCoroutine { cont ->
            val main = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(activity, main, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c != null) cont.resume(c) else cont.resumeWithException(AuthError(-1, "the prompt returned no key"))
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    if (cont.isActive) cont.resumeWithException(AuthError(code, msg.toString()))
                }
            })
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title).setSubtitle(subtitle)
                .setAllowedAuthenticators(ALLOWED)
                .setConfirmationRequired(false)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            cont.invokeOnCancellation { prompt.cancelAuthentication() }
        }
}
