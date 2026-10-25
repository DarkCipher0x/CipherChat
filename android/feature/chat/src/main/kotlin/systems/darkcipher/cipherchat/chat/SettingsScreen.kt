package systems.darkcipher.cipherchat.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import systems.darkcipher.cipherchat.client.Gate
import systems.darkcipher.cipherchat.crypto.fpGroups
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxMonoSmall
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxPanel
import systems.darkcipher.cipherchat.designsystem.DcxScaffold
import systems.darkcipher.cipherchat.designsystem.DcxSectionHeader
import systems.darkcipher.cipherchat.designsystem.DcxThemeStore
import systems.darkcipher.cipherchat.designsystem.DcxThemes

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(model: ChatModel, back: () -> Unit) {
    val e = model.engine
    val ctx = LocalContext.current
    val theme by DcxThemeStore.current.collectAsState()
    var lockMin by remember { mutableStateOf(model.host.autoLockMinutes) }
    var devices by remember { mutableStateOf<List<JsonObject>?>(null) }
    var code by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { try { devices = (e.devices()["devices"] as? JsonArray)?.filterIsInstance<JsonObject>() } catch (x: Exception) { devices = emptyList() } }
    DcxScaffold(title = "Settings", onBack = back) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            DcxSectionHeader("Your identity")
            DcxPanel(Modifier.fillMaxWidth()) {
                SelectionContainer {
                    Text("${e.myUser}@${e.api.origin.host}\n" + fpGroups(e.me.fp), Modifier.padding(14.dp), style = DcxMonoSmall)
                }
            }
            OutlinedButton(shape = DcxButtonShape, onClick = {
                model.run {
                    val p = model.host.prompts
                    val cur = p.ask("Change passphrase", "Your current chat passphrase.", "Current passphrase", secret = true) ?: return@run
                    val next = p.ask("Change passphrase", "A new chat passphrase (16+ characters).", "New passphrase", secret = true) ?: return@run
                    val again = p.ask("Change passphrase", "The new passphrase again.", "New passphrase", secret = true) ?: return@run
                    if (next != again) throw IllegalArgumentException("The two new passphrases don't match.")
                    val c = cur.toCharArray(); val n = next.toCharArray()
                    try { Gate.changePassphrase(e.api, e.me, c, n, p::code) } finally { c.fill('\u0000'); n.fill('\u0000') }
                    p.confirm("Passphrase changed", "Your keys are now sealed with the new passphrase.")
                }
            }) { Text("Change chat passphrase") }

            DcxSectionHeader("Calls")
            if (model.host.fullScreenCalls) Text("Incoming calls ring over the lock screen.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            else {
                Text("Incoming calls only show as a notification. Allow CipherChat to show them full screen, over the lock screen:", color = DcxPalette.Warn)
                OutlinedButton(shape = DcxButtonShape, onClick = { model.host.allowFullScreenCalls() }) { Text("Allow full-screen calls") }
            }

            DcxSectionHeader("Lock")
            Text("Lock automatically after leaving the app for")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(1, 5, 15, 60, 240).forEach { m ->
                    FilterChip(lockMin == m, { lockMin = m; model.host.autoLockMinutes = m }, { Text(if (m < 60) "$m min" else "${m / 60} h") })
                }
            }

            DcxSectionHeader("Theme")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                DcxThemes.all.forEach { t -> FilterChip(theme.id == t.id, { DcxThemeStore.select(ctx, t.id) }, { Text(t.name) }) }
            }

            DcxSectionHeader("Text size")
            val textSize by DcxThemeStore.textSize.collectAsState()
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                DcxThemeStore.textSizes.forEach { p -> FilterChip(textSize == p, { DcxThemeStore.selectTextSize(ctx, p) }, { Text("$p%") }) }
            }
            Text("Messages, emoji and the rest of CipherChat, on top of Android's own font size.", color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall)

            DcxSectionHeader("Paired devices")
            devices?.forEach { d ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(d.strOrNull("name") ?: "device")
                        Text(listOfNotNull(d.strOrNull("id"), if (d["revoked"]?.toString() == "true") "revoked" else null).joinToString(" · "), style = DcxMonoSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    val id = d.strOrNull("id")
                    if (id != null && d["revoked"]?.toString() != "true") TextButton(onClick = {
                        model.run {
                            if (model.host.prompts.confirm("Unpair this device?", "It can't sign in with its pairing any more.", "Unpair", danger = true)) {
                                e.revokeDevice(id); devices = (e.devices()["devices"] as? JsonArray)?.filterIsInstance<JsonObject>()
                            }
                        }
                    }) { Text("Unpair", color = DcxPalette.Bad) }
                }
            }
            if (model.host.pairedDevice)
                Text("Pairing another device needs a sign-in with your password and code or a passkey (not a paired device): use the web chat's /pair, or sign in on this phone instead of pairing.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            else OutlinedButton(shape = DcxButtonShape, onClick = {
                model.run {
                    val name = model.host.prompts.ask("Pair a device", "A name for the new device (e.g. \"laptop\").", "Device name") ?: return@run
                    code = e.pairDevice(name)
                }
            }) { Text("Pair another device") }

            DcxSectionHeader("Session")
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(shape = DcxButtonShape, onClick = { model.host.lock() }) { Text("Lock now") }
                OutlinedButton(shape = DcxButtonShape, onClick = { model.run { model.host.signOut(false) } }) { Text("Sign out") }
            }
            OutlinedButton(shape = DcxButtonShape, onClick = {
                model.run { if (model.host.prompts.confirm("Forget this phone?", "Signs out and removes this server's pairing from the phone.", "Forget", danger = true)) model.host.signOut(true) }
            }) { Text("Sign out and forget this phone", color = DcxPalette.Bad) }

            DcxSectionHeader("About")
            Text("CipherChat ${model.host.version} by DarkCipher Systems\nTLS 1.3 · X25519MLKEM768 only\nMessages: ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, AES-256-GCM",
                style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    code?.let { c ->
        AlertDialog(onDismissRequest = { code = null }, title = { Text("Pairing code") }, text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Enter this on the other device. It works once and only for a short while; anyone who sees it can pair as you.")
                SelectionContainer { Text(c, style = DcxMonoSmall) }
            }
        }, confirmButton = { TextButton(onClick = { code = null }) { Text("Done") } })
    }
}
