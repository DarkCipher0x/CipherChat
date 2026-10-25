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
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import systems.darkcipher.cipherchat.client.AskCode
import systems.darkcipher.cipherchat.client.ChatApi
import systems.darkcipher.cipherchat.client.Gate
import systems.darkcipher.cipherchat.client.Me
import systems.darkcipher.cipherchat.crypto.fpGroups
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxMono
import systems.darkcipher.cipherchat.designsystem.DcxMonoSmall
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxPanel
import systems.darkcipher.cipherchat.designsystem.DcxScaffold

/**
 * In front of the chat (gate.js, the Windows GateView): set up or unlock the identity with the chat passphrase, then
 * pin the owner by comparing safety numbers. The passphrase is a CharArray kept only until the owner is pinned, then
 * wiped. [refresh] fetches the server's state again; [enter] starts the chat with the unlocked identity.
 */
@Composable
fun GateScreen(api: ChatApi, state: () -> JsonObject, refresh: suspend () -> Unit, ask: AskCode,
               enter: suspend (Me) -> Unit, signOut: suspend () -> Unit, selfTest: String?) {
    val scope = rememberCoroutineScope()
    val st = state()
    val meInfo = st["me"] as JsonObject
    val user = meInfo.str("user")
    val owner = (meInfo["owner"] as? JsonPrimitive)?.content == "true"
    val hasIdentity = meInfo.strOrNull("identity_fp") != null
    var busy by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var pass by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    var me by remember { mutableStateOf<Me?>(null) }
    var held by remember { mutableStateOf<CharArray?>(null) }
    var verify by remember { mutableStateOf(false) }
    var same by remember { mutableStateOf(false) }
    DisposableEffect(Unit) { onDispose { held?.fill('\u0000') } }

    fun run(block: suspend () -> Unit) {
        if (busy != null) return
        busy = "…"; error = null
        scope.launch {
            try { block() }
            catch (e: CancellationException) { throw e }
            catch (e: Exception) { error = e.message ?: "That didn't work." }
            finally { busy = null }
        }
    }

    suspend fun finish(m: Me) {
        held?.fill('\u0000'); held = null                                       // the passphrase isn't needed any more
        enter(m)
    }

    suspend fun afterUnlock(m: Me, p: CharArray) {
        me = m
        if (m.anchorFp == null && !owner) { refresh(); held = p; verify = true; return }
        p.fill('\u0000')
        finish(m)
    }

    DcxScaffold(title = "$user@cipherchat") {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).imePadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            DcxPanel(Modifier.fillMaxWidth()) {
                Text("cipherchat 1 // end-to-end encrypted, post-quantum\nsuite  ML-KEM-1024+X25519 · ML-DSA-87+Ed25519 · AES-256-GCM\ntls    1.3, X25519MLKEM768 only\n" +
                    (if (selfTest == null) "[  OK  ] known-answer self-test" else "[FAILED] self-test: $selfTest"),
                    Modifier.padding(14.dp), style = DcxMonoSmall, color = if (selfTest == null) MaterialTheme.colorScheme.primary else DcxPalette.Bad)
            }
            if (busy != null) Text(busy!!, style = DcxMono, color = MaterialTheme.colorScheme.primary)
            if (error != null) Text(error!!, color = DcxPalette.Bad)
            val m = me
            when {
                selfTest != null -> Text("This phone's cryptography failed its self-test, so CipherChat won't run. Update the app or tell the owner.", color = DcxPalette.Bad)
                verify && m != null -> {
                    val sn = Gate.ownerSafetyNumber(state(), m)
                    val ownerUser = state().str("owner")
                    DcxPanel(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Verify the owner", style = MaterialTheme.typography.titleLarge)
                            if (sn == null) Text("The owner ($ownerUser) hasn't set up their chat identity yet, so there's nobody to verify against. You can use the chat once they have.")
                            else {
                                Text("Read this number to $ownerUser (or have them read theirs to you) in person, on a call or through a channel you already trust. Not in the chat, and not by email.")
                                Text(sn.split(' ').chunked(4).joinToString("\n") { it.joinToString(" ") }, style = DcxMono.copy(fontSize = 20.sp, lineHeight = 28.sp),
                                    color = MaterialTheme.colorScheme.primary)
                                Text("You      " + fpGroups(m.fp) + "\nOwner    " + fpGroups(Gate.ownerIdentity(state())!!.str("fp")), style = DcxMonoSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Checkbox(same, { same = it })
                                    Text("The numbers are the same")
                                }
                                Button(shape = DcxButtonShape, onClick = { run { Gate.pinOwner(api, state(), m, held!!, ask); finish(m) } }, enabled = same && busy == null) { Text("Trust the owner") }
                            }
                            TextButton(onClick = { run { finish(m) } }) { Text("Later (nobody can be trusted until you do)") }
                        }
                    }
                }
                !hasIdentity -> DcxPanel(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Set up your chat keys", style = MaterialTheme.typography.titleLarge)
                        Text("Choose a chat passphrase (16+ characters; 4 or more random words works well). It seals your keys on the server with Argon2id; nobody, not even the server, can open them without it. If you lose it, your old messages can't be read.")
                        PassField(pass, { pass = it }, "Chat passphrase")
                        PassField(pass2, { pass2 = it }, "Again")
                        Button(shape = DcxButtonShape, onClick = {
                            val p = pass.toCharArray(); val p2 = pass2.toCharArray(); pass = ""; pass2 = ""
                            run {
                                if (!p.contentEquals(p2)) { p.fill('\u0000'); throw IllegalArgumentException("The two passphrases don't match.") }
                                p2.fill('\u0000')
                                Gate.passProblems(p)?.let { p.fill('\u0000'); throw IllegalArgumentException(it) }
                                try { afterUnlock(Gate.setup(api, state(), p, reset = false, ask = ask) { busy = it }, p) }
                                catch (e: Exception) { p.fill('\u0000'); throw e }
                            }
                        }, enabled = pass.length >= Gate.MIN_PASS && busy == null) { Text("Create my keys") }
                    }
                }
                else -> DcxPanel(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Unlock $user@cipherchat", style = MaterialTheme.typography.titleLarge)
                        Text("Your chat passphrase opens your keys on this phone. It is never sent anywhere.")
                        PassField(pass, { pass = it }, "Chat passphrase")
                        Button(shape = DcxButtonShape, onClick = {
                            val p = pass.toCharArray(); pass = ""
                            run {
                                try { afterUnlock(Gate.unlock(api, state(), p) { busy = it }, p) }
                                catch (e: Exception) { p.fill('\u0000'); throw e }
                            }
                        }, enabled = pass.isNotEmpty() && busy == null) { Text("Unlock") }
                    }
                }
            }
            TextButton(onClick = { run { signOut() } }) { Text("Sign out") }
        }
    }
}

@Composable
private fun PassField(value: String, onChange: (String) -> Unit, label: String) =
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth(), label = { Text(label) }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false))
