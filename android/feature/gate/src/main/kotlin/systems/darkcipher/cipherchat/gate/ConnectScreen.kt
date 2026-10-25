package systems.darkcipher.cipherchat.gate

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxPanel
import systems.darkcipher.cipherchat.designsystem.DcxScaffold
import systems.darkcipher.cipherchat.designsystem.DcxSectionHeader
import systems.darkcipher.cipherchat.designsystem.DcxMono

/** One remembered pairing, as the list shows it. */
class SavedPairing(val title: String, val detail: String)

/** What the connect screen can do (the app's Session behind it). Each throws with a message to show. */
interface ConnectActions {
    suspend fun resume(index: Int)
    fun forget(index: Int)
    suspend fun pair(code: String)
    suspend fun signIn(origin: String, user: String, password: String, code: String)
    suspend fun passkey(origin: String)
}

/**
 * How this phone reaches a server (the Windows ConnectView): a saved pairing, a new pairing code (pasted or scanned
 * as a QR code from the web chat or the Windows app), a passkey, or a password and authenticator code.
 */
@Composable
fun ConnectScreen(saved: List<SavedPairing>, devBuild: Boolean, actions: ConnectActions) {
    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current
    var busy by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var code by remember { mutableStateOf("") }
    var origin by remember { mutableStateOf("https://") }
    var user by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var totp by remember { mutableStateOf("") }

    fun run(what: String, block: suspend () -> Unit) {
        if (busy != null) return
        busy = what; error = null
        scope.launch {
            try { block() }
            catch (e: CancellationException) { throw e }
            catch (e: Exception) { error = e.message ?: "That didn't work." }
            finally { busy = null }
        }
    }

    DcxScaffold(title = "CipherChat") {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).imePadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("Post-quantum end-to-end encrypted chat and calls", color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (busy != null) Text(busy!!, style = DcxMono, color = MaterialTheme.colorScheme.primary)
            if (error != null) Text(error!!, color = DcxPalette.Bad)

            if (saved.isNotEmpty()) {
                DcxSectionHeader("This phone is paired with")
                saved.forEachIndexed { i, s ->
                    DcxPanel(Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(start = 16.dp, end = 4.dp, top = 6.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(s.title, style = MaterialTheme.typography.titleMedium)
                                Text(s.detail, style = DcxMono, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            TextButton(onClick = { run("Signing in over post-quantum TLS…") { actions.resume(i) } }) { Text("Open") }
                            IconButton(onClick = { actions.forget(i) }) { Icon(Icons.Filled.Delete, "Forget this pairing") }
                        }
                    }
                }
            }

            DcxSectionHeader("Pair this phone")
            DcxPanel(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("In the web chat type /pair (or open Devices in the Windows app), then scan the code or paste it here. The code works once.",
                        style = MaterialTheme.typography.bodyMedium)
                    OutlinedTextField(code, { code = it }, Modifier.fillMaxWidth(), label = { Text("Pairing code") }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(shape = DcxButtonShape, onClick = { val c = code; code = ""; run("Pairing…") { actions.pair(c) } }, enabled = code.isNotBlank()) { Text("Pair") }
                        OutlinedButton(shape = DcxButtonShape, onClick = {
                            val opts = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
                            GmsBarcodeScanning.getClient(ctx, opts).startScan()
                                .addOnSuccessListener { b -> b.rawValue?.let { v -> run("Pairing…") { actions.pair(v) } } }
                                .addOnFailureListener { e -> error = "The scanner didn't start: " + e.message }
                        }) { Icon(Icons.Filled.QrCodeScanner, null); Text("  Scan") }
                    }
                }
            }

            DcxSectionHeader("Or sign in")
            DcxPanel(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(origin, { origin = it.trim() }, Modifier.fillMaxWidth(), label = { Text("Server") }, singleLine = true,
                        textStyle = DcxMono, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
                    if (devBuild) Text("Development build: plain http:// to a server on this phone (http://localhost:PORT through adb reverse) is allowed.", style = MaterialTheme.typography.bodySmall, color = DcxPalette.Warn)
                    OutlinedButton(shape = DcxButtonShape, onClick = { run("Waiting for your passkey…") { actions.passkey(origin) } }, enabled = origin.length > 8, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Filled.Key, null); Text("  Sign in with a passkey")
                    }
                    Text("Your phone's passkey, or one in a password manager such as Bitwarden.", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    OutlinedTextField(user, { user = it.trim() }, Modifier.fillMaxWidth(), label = { Text("Username") }, singleLine = true)
                    OutlinedTextField(password, { password = it }, Modifier.fillMaxWidth(), label = { Text("Password") }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
                    OutlinedTextField(totp, { totp = it.filter(Char::isDigit).take(8) }, Modifier.fillMaxWidth(), label = { Text("Authenticator code") }, singleLine = true,
                        textStyle = DcxMono.copy(fontFamily = FontFamily.Monospace), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    Button(shape = DcxButtonShape, onClick = {
                        val p = password; password = ""; val c = totp; totp = ""
                        run("Signing in over post-quantum TLS…") { actions.signIn(origin, user, p, c) }
                    }, enabled = origin.length > 8 && user.isNotEmpty() && password.isNotEmpty() && totp.length >= 6) { Text("Sign in") }
                    Text("Signing in with a password doesn't remember this phone; pairing does.", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Text("CipherChat by DarkCipher Systems · TLS 1.3 with X25519MLKEM768 only", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
