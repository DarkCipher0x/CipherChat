package systems.darkcipher.cipherchat

import android.app.Activity
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Passkeys through Android's Credential Manager: the phone's own (Google Password Manager) or a password manager such as
 * Bitwarden. The server's WebAuthn request goes in as-is and the assertion comes back as the browser's
 * PublicKeyCredential JSON, which is what the server checks. Android signs clientDataJSON with this app's origin
 * ("android:apk-key-hash:..."), so the server must list it (CIPHERCHAT_PASSKEY_APP_ORIGINS) and publish the app in
 * /.well-known/assetlinks.json (docs/ANDROID.md).
 */
class Passkeys(private val activity: Activity) {
    private val cm = CredentialManager.create(activity)

    /** Null when cancelled or there's no passkey for this server. */
    suspend fun sign(publicKey: JsonObject, origin: String): JsonObject? {
        val req = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(publicKey.toString())))
        return try {
            val c = cm.getCredential(activity, req).credential as? PublicKeyCredential ?: return null
            Json.parseToJsonElement(c.authenticationResponseJson) as? JsonObject
        } catch (e: GetCredentialCancellationException) { null }
        catch (e: NoCredentialException) { null }
        catch (e: GetCredentialException) { throw IllegalStateException("The passkey didn't work: " + (e.message ?: e.type)) }
    }
}
