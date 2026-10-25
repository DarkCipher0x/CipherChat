package systems.darkcipher.cipherchat.chat

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.background
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import systems.darkcipher.cipherchat.client.ChatEngine
import systems.darkcipher.cipherchat.client.LineKind
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxMonoSmall
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxPanel
import systems.darkcipher.cipherchat.designsystem.DcxScaffold
import systems.darkcipher.cipherchat.designsystem.DcxStatus
import systems.darkcipher.cipherchat.designsystem.StatusPill

private enum class Page { Rooms, Room, People, RoomInfo, Settings }

/** The unlocked chat: rooms, a room, people, room settings, app settings. [openRoomId] opens one (a notification tap). */
@Composable
fun ChatHome(engine: ChatEngine, host: ChatHost, openRoomId: String?) {
    val model = remember(engine) { ChatModel(engine, host) }
    DisposableEffect(model) { onDispose { model.dispose() } }
    var page by rememberSaveable { mutableStateOf(Page.Rooms) }
    LaunchedEffect(openRoomId, model.rev) {
        if (openRoomId != null && model.room?.id != openRoomId) engine.roomById(openRoomId)?.let { model.open(it); page = Page.Room }
    }
    BackHandler(page != Page.Rooms) {
        page = when (page) { Page.RoomInfo -> Page.Room; else -> { if (page == Page.Room) model.open(null); Page.Rooms } }
    }
    when (page) {
        Page.Rooms -> RoomsScreen(model, open = { model.open(it); page = Page.Room }, people = { page = Page.People }, settings = { page = Page.Settings })
        Page.Room -> {
            val r = model.room
            if (r == null) page = Page.Rooms
            else RoomScreen(model, r, back = { model.open(null); page = Page.Rooms }, info = { page = Page.RoomInfo })
        }
        Page.People -> PeopleScreen(model, back = { page = Page.Rooms }, openDm = { model.open(it); page = Page.Room })
        Page.RoomInfo -> model.room?.let { RoomInfoScreen(model, it, back = { page = Page.Room }, left = { model.open(null); page = Page.Rooms }) } ?: run { page = Page.Rooms }
        Page.Settings -> SettingsScreen(model, back = { page = Page.Rooms })
    }
}

@Composable
private fun RoomsScreen(model: ChatModel, open: (systems.darkcipher.cipherchat.client.Room) -> Unit, people: () -> Unit, settings: () -> Unit) {
    val e = model.engine
    @Suppress("UNUSED_VARIABLE") val tick = model.rev
    var creating by remember { mutableStateOf(false) }
    DcxScaffold(title = e.myUser, actions = {
        IconButton(onClick = people) { Icon(Icons.Filled.People, "People") }
        IconButton(onClick = settings) { Icon(Icons.Filled.Settings, "Settings") }
        IconButton(onClick = { model.host.lock() }) { Icon(Icons.Filled.Lock, "Lock") }
    }) {
        Box(Modifier.fillMaxSize()) {
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    Row(Modifier.padding(top = 10.dp, bottom = 2.dp), horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                        StatusPill(if (model.online) DcxStatus.Good else DcxStatus.Warn, when { !model.online -> "reconnecting…"; e.api.origin.scheme == "https" -> "connected · TLS 1.3 X25519MLKEM768"; else -> "connected · development server (no TLS)" })
                        if (e.ownerProblem.isNotEmpty()) StatusPill(DcxStatus.Bad, "trust: " + e.ownerProblem)
                    }
                }
                model.banner?.let { (k, t) ->
                    item {
                        Text(t, Modifier.fillMaxWidth().clickable { model.banner = null }.padding(vertical = 4.dp),
                            color = if (k == LineKind.ERR) DcxPalette.Bad else if (k == LineKind.WARN) DcxPalette.Warn else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                val rooms = e.roomList.sortedWith(compareByDescending<systems.darkcipher.cipherchat.client.Room> { it.unread > 0 }.thenBy { it.label(e.myUser) })
                if (rooms.isEmpty()) item { Text("No rooms yet. " + (if (e.canCreateRooms) "Make one with +, or open People to message someone." else "Open People to message someone."), color = MaterialTheme.colorScheme.onSurfaceVariant) }
                items(rooms, key = { it.id }) { r ->
                    DcxPanel(Modifier.fillMaxWidth().clickable { open(r) }) {
                        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(r.label(e.myUser), style = MaterialTheme.typography.titleMedium)
                                val sub = listOfNotNull(r.topic.takeIf { it.isNotEmpty() }, if (r.kind == "dm") null else r.members.size.let { n -> if (n == 1) "1 member" else "$n members" },
                                    if (r.retentionDays > 0) "keeps ${r.retentionDays} d" else null).joinToString(" · ")
                                if (sub.isNotEmpty()) Text(sub, style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            if (r.unread > 0) Box(Modifier.background(MaterialTheme.colorScheme.primary, RoundedCornerShape(10.dp)).padding(horizontal = 9.dp, vertical = 3.dp)) {
                                Text(r.unread.toString(), color = MaterialTheme.colorScheme.onPrimary, style = MaterialTheme.typography.labelMedium)
                            }
                        }
                    }
                }
                item { Box(Modifier.size(88.dp)) }
            }
            if (e.canCreateRooms) FloatingActionButton(onClick = { creating = true }, Modifier.align(Alignment.BottomEnd).padding(20.dp),
                containerColor = MaterialTheme.colorScheme.primary) { Icon(Icons.Filled.Add, "New private room") }
        }
    }
    if (creating) NewRoomDialog(model, done = { r -> creating = false; if (r != null) open(r) })
}
