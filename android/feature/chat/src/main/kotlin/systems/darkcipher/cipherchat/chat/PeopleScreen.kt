package systems.darkcipher.cipherchat.chat

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import systems.darkcipher.cipherchat.client.Person
import systems.darkcipher.cipherchat.client.Room
import systems.darkcipher.cipherchat.client.TrustLevel
import systems.darkcipher.cipherchat.crypto.fpGroups
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxMono
import systems.darkcipher.cipherchat.designsystem.DcxMonoSmall
import systems.darkcipher.cipherchat.designsystem.DcxPanel
import systems.darkcipher.cipherchat.designsystem.DcxScaffold
import systems.darkcipher.cipherchat.designsystem.DcxStatus
import systems.darkcipher.cipherchat.designsystem.StatusPill

fun TrustLevel.status() = when (this) {
    TrustLevel.OK -> DcxStatus.Good
    TrustLevel.PENDING -> DcxStatus.Warn
    TrustLevel.NONE -> DcxStatus.Idle
    TrustLevel.BAD -> DcxStatus.Bad
}

/** Everyone on the server and whether this phone can trust them: tap for the safety number, a message, or (owner) certify. */
@Composable
fun PeopleScreen(model: ChatModel, back: () -> Unit, openDm: (Room) -> Unit) {
    val e = model.engine
    @Suppress("UNUSED_VARIABLE") val tick = model.rev
    var shown by remember { mutableStateOf<Person?>(null) }
    DcxScaffold(title = "People", onBack = back) {
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item { Text("Only identities certified by the owner you verified are trusted. The server's word counts for nothing.",
                Modifier.padding(vertical = 10.dp), color = MaterialTheme.colorScheme.onSurfaceVariant) }
            items(e.people.values.sortedBy { it.user }.toList(), key = { it.user }) { p ->
                DcxPanel(Modifier.fillMaxWidth().clickable { shown = p }) {
                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(p.user + (if (p.user == e.myUser) "  (you)" else "") + (if (p.owner) "  · owner" else "") + (if (p.user.startsWith("addon.")) "  · add-on" else ""), style = MaterialTheme.typography.titleMedium)
                            if (p.displayName.isNotEmpty()) Text(p.displayName, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        StatusPill(p.trust.status(), p.trust.name.lowercase())
                    }
                }
            }
        }
    }
    shown?.let { p -> PersonDialog(model, p, close = { shown = null }, openDm = { r -> shown = null; openDm(r) }) }
}

@Composable
private fun PersonDialog(model: ChatModel, p: Person, close: () -> Unit, openDm: (Room) -> Unit) {
    val e = model.engine
    var same by remember { mutableStateOf(false) }
    val sn = if (p.user != e.myUser) e.safetyNumber(p) else ""
    AlertDialog(onDismissRequest = close, title = { Text(p.user) }, text = {
        Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            StatusPill(p.trust.status(), p.why)
            if (p.fp != null) Text("Fingerprint\n" + fpGroups(p.fp!!), style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (sn.isNotEmpty()) {
                Text("Safety number (the same on both phones only if nobody is in the middle):")
                Text(sn.split(' ').chunked(4).joinToString("\n") { it.joinToString(" ") }, style = DcxMono.copy(fontSize = 17.sp, lineHeight = 24.sp),
                    color = MaterialTheme.colorScheme.primary)
            }
            if (e.iAmOwner && p.user != e.myUser && p.fp != null && p.trust != TrustLevel.OK) {
                Text("Certify only after comparing this number with ${p.user} in person or on a call you trust.")
                Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(same, { same = it }); Text("The numbers are the same") }
            }
        }
    }, confirmButton = {
        Row {
            if (e.iAmOwner && p.user != e.myUser && p.fp != null && p.trust != TrustLevel.OK)
                TextButton(onClick = { model.run("Certifying…") { e.certify(p) }; close() }, enabled = same) { Text("Certify") }
            if (e.iAmOwner && p.user != e.myUser && p.trust == TrustLevel.OK)
                TextButton(onClick = {
                    model.run { if (model.host.prompts.confirm("Revoke ${p.user}?", "Their certificate is withdrawn; rooms renew their keys without them.", "Revoke", danger = true)) e.revoke(p) }
                    close()
                }) { Text("Revoke") }
            if (p.user != e.myUser && p.fp != null) TextButton(onClick = { model.run { val r = e.openDm(p.user); kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { openDm(r) } } }) { Text("Message") }
            TextButton(onClick = close) { Text("Close") }
        }
    })
}
