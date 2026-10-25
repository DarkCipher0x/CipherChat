package systems.darkcipher.cipherchat.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import systems.darkcipher.cipherchat.client.Room
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxMonoSmall
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxPanel
import systems.darkcipher.cipherchat.designsystem.DcxScaffold
import systems.darkcipher.cipherchat.designsystem.DcxSectionHeader
import systems.darkcipher.cipherchat.designsystem.StatusPill

private fun days(d: Long) = if (d == 0L) "forever" else "$d days"

/** A room's members, key and settings. Admins change members (the room key is renewed for them) and settings. */
@Composable
fun RoomInfoScreen(model: ChatModel, room: Room, back: () -> Unit, left: () -> Unit) {
    val e = model.engine
    @Suppress("UNUSED_VARIABLE") val tick = model.rev
    val admin = room.myRole == "admin"
    var name by remember(room.id) { mutableStateOf(room.name) }
    var topic by remember(room.id) { mutableStateOf(room.topic) }
    var keep by remember(room.id) { mutableStateOf(room.retentionDays) }
    var adding by remember { mutableStateOf(false) }
    DcxScaffold(title = room.label(e.myUser), onBack = back) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            DcxSectionHeader("Encryption")
            DcxPanel(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Room key #${room.epoch} · ML-KEM-1024 + X25519, signed ML-DSA-87 + Ed25519", style = DcxMonoSmall)
                    Text("Held by: " + room.epochRecipients.joinToString(", ").ifEmpty { "nobody yet" }, style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (room.needsRotation) Text("Members changed: the key is renewed before the next message.", color = DcxPalette.Warn)
                    OutlinedButton(shape = DcxButtonShape, onClick = { model.run("Making a new room key…") { e.rotateNow(room) } }) { Text("Renew the key now") }
                }
            }
            DcxSectionHeader("Members")
            room.members.forEach { (u, role) ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(u + if (role == "admin") "  · admin" else "", Modifier.weight(1f))
                    e.people[u]?.let { StatusPill(it.trust.status(), it.trust.name.lowercase()) }
                    if (admin && room.kind != "dm" && u != e.myUser) TextButton(onClick = {
                        model.run { if (model.host.prompts.confirm("Remove $u?", "They lose access; the room key is renewed without them.", "Remove", danger = true)) e.changeMembers(room, emptyList(), listOf(u)) }
                    }) { Text("Remove", color = DcxPalette.Bad) }
                }
            }
            if (admin && room.kind != "dm") OutlinedButton(shape = DcxButtonShape, onClick = { adding = true }) { Text("Add people") }
            if (admin && room.kind != "dm") {
                DcxSectionHeader("Settings")
                OutlinedTextField(name, { name = it }, Modifier.fillMaxWidth(), label = { Text("Name") }, singleLine = true)
                OutlinedTextField(topic, { topic = it }, Modifier.fillMaxWidth(), label = { Text("Topic") }, singleLine = true)
                Text("Keep messages for")
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    e.retentionChoices.forEach { d -> FilterChip(keep == d, { keep = d }, { Text(days(d)) }) }
                }
                OutlinedButton(shape = DcxButtonShape, onClick = { model.run("Saving…") { e.updateRoom(room, name, topic, keep) } }) { Text("Save") }
            }
            DcxSectionHeader("Leave")
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(shape = DcxButtonShape, onClick = {
                    model.run { if (model.host.prompts.confirm("Leave ${room.label(e.myUser)}?", "You'll stop receiving its messages.", "Leave", danger = true)) { e.leave(room); withContext(Dispatchers.Main) { left() } } }
                }) { Text("Leave", color = DcxPalette.Bad) }
                if (admin) OutlinedButton(shape = DcxButtonShape, onClick = {
                    model.run { if (model.host.prompts.confirm("Delete ${room.label(e.myUser)}?", "Every message and file in it is deleted from the server for everyone.", "Delete", danger = true)) { e.deleteRoom(room); withContext(Dispatchers.Main) { left() } } }
                }) { Text("Delete", color = DcxPalette.Bad) }
            }
        }
    }
    if (adding) PickPeople(model, "Add people", exclude = room.members.map { it.first }.toSet(), done = { picked ->
        adding = false
        if (picked.isNotEmpty()) model.run("Adding…") { e.changeMembers(room, picked, emptyList()) }
    })
}

@Composable
fun PickPeople(model: ChatModel, title: String, exclude: Set<String>, done: (List<String>) -> Unit) {
    val e = model.engine
    val picked = remember { mutableStateListOf<String>() }
    AlertDialog(onDismissRequest = { done(emptyList()) }, title = { Text(title) }, text = {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            e.people.values.filter { it.user !in exclude && it.user != e.myUser }.sortedBy { it.user }.forEach { p ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(p.user in picked, { if (it) picked.add(p.user) else picked.remove(p.user) })
                    Text(p.user, Modifier.weight(1f))
                    StatusPill(p.trust.status(), p.trust.name.lowercase())
                }
            }
        }
    }, confirmButton = { TextButton(onClick = { done(picked.toList()) }) { Text("OK") } },
        dismissButton = { TextButton(onClick = { done(emptyList()) }) { Text("Cancel") } })
}

@Composable
fun NewRoomDialog(model: ChatModel, done: (Room?) -> Unit) {
    val e = model.engine
    var name by remember { mutableStateOf("") }
    var topic by remember { mutableStateOf("") }
    var keep by remember { mutableStateOf(e.retentionChoices.firstOrNull() ?: 0L) }
    val members = remember { mutableStateListOf<String>() }
    AlertDialog(onDismissRequest = { done(null) }, title = { Text("New private room") }, text = {
        Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(name, { name = it.filter { c -> c.isLetterOrDigit() || c in "-_." }.take(40) }, label = { Text("#name") }, singleLine = true)
            OutlinedTextField(topic, { topic = it.take(200) }, label = { Text("Topic") }, singleLine = true)
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) { e.retentionChoices.forEach { d -> FilterChip(keep == d, { keep = d }, { Text(days(d)) }) } }
            Text("Members")
            e.people.values.filter { it.user != e.myUser }.sortedBy { it.user }.forEach { p ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(p.user in members, { if (it) members.add(p.user) else members.remove(p.user) })
                    Text(p.user, Modifier.weight(1f)); StatusPill(p.trust.status(), p.trust.name.lowercase())
                }
            }
        }
    }, confirmButton = {
        TextButton(onClick = {
            val n = name; val t = topic; val k = keep; val m = members.toList()
            model.run("Creating #$n…") { val r = e.createRoom(n, t, k, m); withContext(Dispatchers.Main) { done(r) } }
        }, enabled = name.isNotBlank()) { Text("Create") }
    }, dismissButton = { TextButton(onClick = { done(null) }) { Text("Cancel") } })
}
