package systems.darkcipher.cipherchat.chat

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.graphics.drawable.AnimatedImageDrawable
import android.graphics.drawable.Drawable
import android.widget.ImageView
import android.net.Uri
import android.os.PersistableBundle
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.content.MediaType
import androidx.compose.foundation.content.consume
import androidx.compose.foundation.content.contentReceiver
import androidx.compose.foundation.content.hasMediaType
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.EmojiEmotions
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.LocalFireDepartment
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import systems.darkcipher.cipherchat.client.ChatEngine
import systems.darkcipher.cipherchat.client.ChatMessage
import systems.darkcipher.cipherchat.client.Entry
import systems.darkcipher.cipherchat.client.FileRef
import systems.darkcipher.cipherchat.client.LineKind
import systems.darkcipher.cipherchat.client.Outgoing
import systems.darkcipher.cipherchat.client.Room
import systems.darkcipher.cipherchat.crypto.Files
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxMono
import systems.darkcipher.cipherchat.designsystem.DcxMonoSmall
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxScaffold
import systems.darkcipher.cipherchat.designsystem.dcx
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val BURNS = listOf(0, 10, 30, 60, 300)
private val HHMM = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault())

private class Pending(val name: String, val bytes: ByteArray, val mime: String?, val thumb: ByteArray?, val w: Int?, val h: Int?)

@Composable
fun RoomScreen(model: ChatModel, room: Room, back: () -> Unit, info: () -> Unit) {
    val e = model.engine
    val ctx = LocalContext.current
    @Suppress("UNUSED_VARIABLE") val tick = model.rev
    @Suppress("UNUSED_VARIABLE") val changed = model.entryRev
    val input = remember(room.id) { TextFieldState() }
    var replyTo by remember(room.id) { mutableStateOf<ChatMessage?>(null) }
    var editing by remember(room.id) { mutableStateOf<ChatMessage?>(null) }
    var burn by remember(room.id) { mutableStateOf(0) }
    val pending = remember(room.id) { mutableStateListOf<Pending>() }
    var viewing by remember { mutableStateOf<Pair<FileRef, Bitmap>?>(null) }
    var saving by remember { mutableStateOf<FileRef?>(null) }
    var sheet by remember { mutableStateOf<String?>(null) }           // "emoji" or "gif"
    var reactTo by remember { mutableStateOf<ChatMessage?>(null) }    // the emoji sheet picks a reaction for this message
    val list = rememberLazyListState()

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        model.run("Reading files…") { for (u in uris.take(10 - pending.size)) readPending(ctx, u)?.let { withContext(Dispatchers.Main) { pending.add(it) } } }
    }
    val pickGif = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        model.run("Reading GIFs…") { for (u in uris.take(10 - pending.size)) readPending(ctx, u)?.let { withContext(Dispatchers.Main) { pending.add(it) } } }
    }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val f = saving ?: return@rememberLauncherForActivityResult
        saving = null
        if (uri != null) model.run("Decrypting ${f.safeName}…") {
            val bytes = e.fetchFile(room, f)
            ctx.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
        }
    }

    LaunchedEffect(model.timeline.size) { if (model.timeline.isNotEmpty()) list.animateScrollToItem(model.timeline.size) }

    DcxScaffold(title = room.label(e.myUser), onBack = back, actions = {
        val people = room.members.map { it.first }.filter { it != e.myUser }
        IconButton(onClick = { model.host.startCall(room, "audio", people) }, enabled = people.isNotEmpty()) { Icon(Icons.Filled.Call, "Voice call") }
        IconButton(onClick = { model.host.startCall(room, "video", people) }, enabled = people.isNotEmpty()) { Icon(Icons.Filled.Videocam, "Video call") }
        IconButton(onClick = info) { Icon(Icons.Filled.Info, "Room") }
    }) {
        Column(Modifier.fillMaxSize().imePadding()) {
            LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 10.dp), state = list, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (room.moreHistory) item { TextButton(onClick = { model.run { e.loadOlder(room) } }) { Text("Load older messages") } }
                items(model.timeline, key = { System.identityHashCode(it) }) { en ->
                    val m = en.message
                    val og = en.outgoing
                    if (og != null) PendingRow(model, og)
                    else if (m == null) LineRow(en)
                    else MessageRow(model, room, m, en,
                        reply = { replyTo = it; editing = null },
                        edit = { editing = it; replyTo = null; input.setTextAndPlaceCursorAtEnd(it.text) },
                        view = { f, b -> viewing = f to b },
                        save = { f -> saving = f; save.launch(f.safeName) },
                        moreReactions = { reactTo = it; sheet = "emoji" })
                }
                item { Box(Modifier.size(4.dp)) }
            }
            model.status?.let { Text(it, Modifier.padding(horizontal = 14.dp), style = DcxMonoSmall, color = MaterialTheme.colorScheme.primary) }
            model.banner?.let { (k, t) ->
                Text(t, Modifier.fillMaxWidth().clickable { model.banner = null }.padding(horizontal = 14.dp, vertical = 2.dp), style = MaterialTheme.typography.bodySmall,
                    color = if (k == LineKind.ERR) DcxPalette.Bad else DcxPalette.Warn)
            }
            replyTo?.let { Bar("Replying to ${it.from}: " + firstLine(it.text)) { replyTo = null } }
            editing?.let { Bar("Editing your message") { editing = null; input.clearText() } }
            if (pending.isNotEmpty()) Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                pending.forEach { p -> Chip(p.name + " · " + ChatModel.human(p.bytes.size.toLong())) { pending.remove(p) } }
            }
            Composer(input, burn, { burn = BURNS[(BURNS.indexOf(burn) + 1) % BURNS.size] },
                attach = { pick.launch(arrayOf("*/*")) }, canAttach = editing == null && pending.size < 10,
                emoji = { reactTo = null; sheet = "emoji" }, gif = { sheet = "gif" },
                // GIFs and stickers from the keyboard (Gboard, SwiftKey, Samsung): read at once (the keyboard's permission
                // to the file is short-lived) and added as encrypted attachments like any picked file
                keyboardMedia = { uri ->
                    if (editing == null && pending.size < 10) try { readPending(ctx, uri)?.let { pending.add(it) } }
                    catch (x: Exception) { model.banner = LineKind.ERR to (x.message ?: "That couldn't be added.") }
                },
                send = {
                    val t = input.text.toString().trim()
                    val files = pending.toList()
                    val re = replyTo?.id
                    val ed = editing
                    val b = burn
                    if (t.isEmpty() && files.isEmpty()) return@Composer
                    input.clearText(); pending.clear(); replyTo = null; editing = null
                    if (b == 0) files.filter { Files.sniff(it.bytes) == "image/gif" }.forEach { model.rememberGif(it.name, it.bytes) }
                    when {
                        ed != null -> model.run { e.edit(room, ed, t) }
                        files.isNotEmpty() -> model.run {
                            e.sendFiles(room, t, files.map { ChatEngine.OutgoingFile(it.name, it.bytes, it.mime, it.thumb, it.w, it.h) }, re, b)
                        }
                        t == "/call" || t == "/voice" -> model.host.startCall(room, "audio", room.members.map { it.first }.filter { it != e.myUser })
                        t == "/video" -> model.host.startCall(room, "video", room.members.map { it.first }.filter { it != e.myUser })
                        t.startsWith("/me ") -> model.run { e.sendText(room, t.removePrefix("/me ").trim(), re, b, action = true) }
                        else -> model.run { e.sendText(room, t, re, b) }
                    }
                })
        }
    }
    viewing?.let { (f, bmp) -> ImageViewer(f, bmp, close = { viewing = null }, save = { saving = f; viewing = null; save.launch(f.safeName) }) }
    when (sheet) {
        "emoji" -> EmojiPicker(onPick = { emo ->
            val target = reactTo
            if (target != null) { sheet = null; reactTo = null; model.run { e.react(room, target, emo, !target.myReaction(e.myUser, emo)) } }
            else input.edit { val s = selection; replace(s.min, s.max, emo); selection = TextRange(s.min + emo.length) }
        }, onDismiss = { sheet = null; reactTo = null })
        "gif" -> GifPicker(model, onPick = { name, bytes ->
            sheet = null
            if (editing == null && pending.size < 10) pending.add(pendingFrom(name, bytes, "image/gif"))
        }, onChoose = { sheet = null; pickGif.launch(arrayOf("image/gif")) }, onDismiss = { sheet = null })
    }
}

private fun firstLine(s: String, max: Int = 60) = s.lineSequence().firstOrNull().orEmpty().let { if (it.length > max) it.take(max) + "…" else it }

@Composable
private fun LineRow(en: Entry) {
    val c = when (en.kind) {
        LineKind.ERR -> DcxPalette.Bad
        LineKind.WARN -> DcxPalette.Warn
        LineKind.OK -> DcxPalette.Good
        LineKind.SERVER -> MaterialTheme.colorScheme.primary.copy(alpha = 0.8f)
        LineKind.SYS -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val time = if (en.at > 0) HHMM.format(Instant.ofEpochSecond(en.at)) + " " else ""
    Text(time + en.who + " " + en.text, style = DcxMonoSmall, color = c, modifier = Modifier.padding(vertical = 2.dp))
}

@OptIn(ExperimentalFoundationApi::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun MessageRow(model: ChatModel, room: Room, m: ChatMessage, en: Entry, reply: (ChatMessage) -> Unit, edit: (ChatMessage) -> Unit,
                       view: (FileRef, Bitmap) -> Unit, save: (FileRef) -> Unit, moreReactions: (ChatMessage) -> Unit) {
    val e = model.engine
    val ctx = LocalContext.current
    var menu by remember { mutableStateOf(false) }
    val mine = m.mine
    val shape = RoundedCornerShape(14.dp)
    Column(Modifier.fillMaxWidth(), horizontalAlignment = if (mine) Alignment.End else Alignment.Start) {
        Box {
            Column(Modifier.widthIn(max = 320.dp)
                .background(if (mine) dcx().hover else dcx().surface.copy(alpha = 0.85f), shape)
                .border(1.dp, if (mine) MaterialTheme.colorScheme.primary.copy(alpha = 0.35f) else dcx().line, shape)
                .combinedClickable(onClick = {}, onLongClick = { if (m.burn == 0) menu = true })
                .padding(horizontal = 12.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text((if (mine) "you" else m.from) + " · " + HHMM.format(Instant.ofEpochSecond(m.at)) + (if (m.editedSeq > 0) " · edited" else ""),
                    style = DcxMonoSmall, color = if (mine) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                m.replyTo?.let { id -> e.messageById(room, id)?.let { t -> Text("↪ " + t.from + ": " + firstLine(t.text, 50), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontStyle = FontStyle.Italic) } }
                if (m.burn > 0) BurnBody(model, room, m) else {
                    val jumbo = m.kind != "me" && isJumbo(m.text)                // a message of just 1-3 emoji shows them big
                    if (m.text.isNotEmpty()) Text(if (m.kind == "me") "* ${m.from} ${m.text}" else m.text,
                        style = if (jumbo) MaterialTheme.typography.bodyLarge.copy(fontSize = 40.sp, lineHeight = 48.sp) else MaterialTheme.typography.bodyLarge,
                        fontStyle = if (m.kind == "me") FontStyle.Italic else FontStyle.Normal)
                    m.files.forEach { f -> FileView(model, room, f, view, save) }
                }
            }
            DropdownMenu(menu, { menu = false }) {
                Row(Modifier.padding(horizontal = 8.dp)) {
                    EmojiSets.quick.forEach { q -> TextButton(onClick = { menu = false; model.run { e.react(room, m, q, !m.myReaction(e.myUser, q)) } }) { Text(q) } }
                }
                DropdownMenuItem({ Text("More reactions…") }, { menu = false; moreReactions(m) })
                DropdownMenuItem({ Text("Reply") }, { menu = false; reply(m) })
                if (m.text.isNotEmpty()) DropdownMenuItem({ Text("Copy") }, { menu = false; copySensitive(ctx, m.text) })
                if (mine && m.kind != "file") DropdownMenuItem({ Text("Edit") }, { menu = false; edit(m) })
                if (mine || room.myRole == "admin") DropdownMenuItem({ Text("Delete for everyone", color = DcxPalette.Bad) }, {
                    menu = false
                    model.run { if (model.host.prompts.confirm("Delete this message?", "It's removed from the server and from everyone's screen.", "Delete", danger = true)) e.redact(room, en.seq) }
                })
            }
        }
        val reactions = m.reactions
        if (reactions.isNotEmpty()) FlowRow(Modifier.padding(top = 2.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            reactions.forEach { (emoji, users) ->
                val on = e.myUser in users
                Text("$emoji ${users.size}", Modifier.background(if (on) MaterialTheme.colorScheme.primary.copy(alpha = 0.2f) else dcx().surface, RoundedCornerShape(10.dp))
                    .clickable { model.run { e.react(room, m, emoji, !on) } }.padding(horizontal = 8.dp, vertical = 2.dp), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** A message of yours still on its way: waiting for the network, sending, or refused (with Retry and Discard). */
@Composable
private fun PendingRow(model: ChatModel, o: Outgoing) {
    @Suppress("UNUSED_VARIABLE") val changed = model.entryRev
    val shape = RoundedCornerShape(14.dp)
    val failed = o.state == Outgoing.State.FAILED
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.End) {
        Column(Modifier.widthIn(max = 320.dp)
            .background(dcx().hover.copy(alpha = 0.6f), shape)
            .border(1.dp, if (failed) DcxPalette.Bad else MaterialTheme.colorScheme.primary.copy(alpha = 0.25f), shape)
            .padding(horizontal = 12.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(o.preview, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.75f))
            val status = when (o.state) {
                Outgoing.State.QUEUED -> "⏳ queued · sends when you're back online" + (o.note?.takeIf { o.attempts > 0 }?.let { " ($it)" } ?: "")
                Outgoing.State.SENDING -> "↑ sending" + (o.note?.let { " · $it" } ?: "") + "…"
                Outgoing.State.SENT -> "✓ sent"
                Outgoing.State.FAILED -> "✕ not sent: " + (o.note ?: "refused")
            }
            Text(status, style = DcxMonoSmall, color = if (failed) DcxPalette.Bad else MaterialTheme.colorScheme.onSurfaceVariant)
            if (o.state == Outgoing.State.FAILED || o.state == Outgoing.State.QUEUED) Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (failed) TextButton(onClick = { model.engine.retry(o) }) { Text("Retry") }
                TextButton(onClick = { model.engine.discard(o) }) { Text("Discard", color = DcxPalette.Bad) }
            }
        }
    }
}

/** Burn messages: hidden until tapped, then shown for their seconds and wiped from this phone (the server destroys them once everyone has opened them). */
@Composable
private fun BurnBody(model: ChatModel, room: Room, m: ChatMessage) {
    var left by remember(m.id) { mutableStateOf(if (m.revealed) m.burn else -1) }
    if (left < 0 && !m.mine) {
        Row(Modifier.clickable { left = m.burn; model.run { model.engine.revealBurn(room, m) } }, verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.LocalFireDepartment, null, tint = DcxPalette.Warn)
            Text("  Burn message · tap to read (${m.burn} s, then gone)", color = DcxPalette.Warn)
        }
        return
    }
    if (m.mine) { Text(m.text, style = MaterialTheme.typography.bodyLarge); Text("🔥 burns ${m.burn} s after it's opened", style = DcxMonoSmall, color = DcxPalette.Warn); return }
    LaunchedEffect(m.id) { while (left > 0) { delay(1000); left-- }; model.engine.burnOut(room, m) }
    Text(m.text, style = MaterialTheme.typography.bodyLarge)
    m.files.forEach { f -> Text("📎 " + f.safeName, style = MaterialTheme.typography.bodySmall) }
    Text("🔥 $left s", style = DcxMonoSmall, color = DcxPalette.Warn)
}

@Composable
private fun FileView(model: ChatModel, room: Room, f: FileRef, view: (FileRef, Bitmap) -> Unit, save: (FileRef) -> Unit) {
    val ctx = LocalContext.current
    // GIFs play inline (decoded in memory by Android's own decoder), unless animations are turned off on this phone
    if (f.kind == "image" && f.mime == "image/gif" && f.size <= GIF_INLINE_MAX && animationsOn(ctx)) {
        val anim by produceState<Drawable?>(null, f.blob) {
            value = try {
                val bytes = model.engine.fetchFile(room, f)
                if (Files.sniff(bytes) != "image/gif") null
                else withContext(Dispatchers.Default) { ImageDecoder.decodeDrawable(ImageDecoder.createSource(ByteBuffer.wrap(bytes))) }
                    .also { if (it is AnimatedImageDrawable) model.rememberGif(f.safeName, bytes) }     // offered again in the GIF sheet
            } catch (x: Exception) { null }
        }
        val d = anim
        if (d is AnimatedImageDrawable) {
            Column {
                AndroidView({ c -> ImageView(c).apply { adjustViewBounds = true; scaleType = ImageView.ScaleType.FIT_START; contentDescription = f.safeName } },
                    Modifier.heightIn(max = 260.dp).clickable {
                        model.run("Decrypting…") {
                            val full = ChatModel.decode(model.engine.fetchFile(room, f), 2048) ?: throw IllegalStateException("That image can't be shown.")
                            withContext(Dispatchers.Main) { view(f, full) }
                        }
                    }, update = { iv -> if (iv.drawable !== d) { iv.setImageDrawable(d); d.start() } })
                Text("GIF · " + f.safeName, style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            return
        }
    }
    if (f.kind == "image" && (f.thumb != null || f.size <= 8_000_000)) {
        val bmp by produceState<Bitmap?>(null, f.blob) { value = try { model.thumb(room, f.thumb ?: f, 640) } catch (x: Exception) { null } }
        val b = bmp
        if (b != null) {
            Image(b.asImageBitmap(), f.safeName, Modifier.heightIn(max = 260.dp).clickable {
                model.run("Decrypting…") {
                    val full = ChatModel.decode(model.engine.fetchFile(room, f), 2048) ?: throw IllegalStateException("That image can't be shown.")
                    withContext(Dispatchers.Main) { view(f, full) }
                }
            }, contentScale = ContentScale.Fit)
            return
        }
    }
    Row(Modifier.clickable { save(f) }.padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Filled.AttachFile, null, tint = MaterialTheme.colorScheme.primary)
        Column {
            Text(f.safeName, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(ChatModel.human(f.size) + " · tap to decrypt and save", style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ImageViewer(f: FileRef, bmp: Bitmap, close: () -> Unit, save: () -> Unit) {
    Dialog(onDismissRequest = close, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(f.safeName, Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                TextButton(onClick = save) { Text("Save") }
                IconButton(onClick = close) { Icon(Icons.Filled.Close, "Close") }
            }
            Image(bmp.asImageBitmap(), f.safeName, Modifier.fillMaxSize(), contentScale = ContentScale.Fit)
        }
    }
}

@Composable
private fun Bar(text: String, cancel: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(text, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary, maxLines = 1)
        IconButton(onClick = cancel) { Icon(Icons.Filled.Close, "Cancel") }
    }
}

@Composable
private fun Chip(text: String, remove: () -> Unit) {
    Row(Modifier.background(dcx().surfaceRaised, RoundedCornerShape(10.dp)).padding(start = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(text, style = MaterialTheme.typography.bodySmall, maxLines = 1)
        IconButton(onClick = remove, Modifier.size(32.dp)) { Icon(Icons.Filled.Close, "Remove", Modifier.size(16.dp)) }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun Composer(input: TextFieldState, burn: Int, cycleBurn: () -> Unit, attach: () -> Unit, canAttach: Boolean,
                     emoji: () -> Unit, gif: () -> Unit, keyboardMedia: (Uri) -> Unit, send: () -> Unit) {
    var attachMenu by remember { mutableStateOf(false) }
    Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
        Box {
            IconButton(onClick = { attachMenu = true }, enabled = canAttach) { Icon(Icons.Filled.AttachFile, "Attach files or a GIF") }
            DropdownMenu(attachMenu, { attachMenu = false }) {
                DropdownMenuItem({ Text("Files, pictures, videos…") }, { attachMenu = false; attach() })
                DropdownMenuItem({ Text("GIF…") }, { attachMenu = false; gif() })
            }
        }
        IconButton(onClick = cycleBurn) {
            Box(contentAlignment = Alignment.Center) {
                Icon(Icons.Filled.LocalFireDepartment, if (burn == 0) "Burn after reading: off" else "Burns $burn s after it's opened",
                    tint = if (burn == 0) MaterialTheme.colorScheme.onSurfaceVariant else DcxPalette.Warn)
                if (burn > 0) Text(burn.toString(), Modifier.align(Alignment.BottomEnd), style = DcxMonoSmall, color = DcxPalette.Warn)
            }
        }
        OutlinedTextField(input, Modifier.weight(1f).contentReceiver { content ->
            if (!content.hasMediaType(MediaType.Image)) return@contentReceiver content
            content.consume { item -> item.uri?.let { keyboardMedia(it); true } ?: false }
        }, placeholder = { Text("Message (encrypted)", style = DcxMono) }, lineLimits = TextFieldLineLimits.MultiLine(maxHeightInLines = 5),
            trailingIcon = { IconButton(onClick = emoji) { Icon(Icons.Filled.EmojiEmotions, "Insert emoji") } })
        IconButton(onClick = send) { Icon(Icons.AutoMirrored.Filled.Send, "Send", tint = MaterialTheme.colorScheme.primary) }
    }
}

/** Copies text marked sensitive, so Android doesn't show it in the clipboard preview or sync it. */
private fun copySensitive(ctx: Context, text: String) {
    val clip = ClipData.newPlainText("message", text)
    clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}

/** Reads a picked file (100 MB at most) and, for pictures, makes a small preview that travels encrypted beside it. */
private fun readPending(ctx: Context, uri: Uri): Pending? {
    val cr = ctx.contentResolver
    var name = "attachment"
    var size = -1L
    cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
        if (c.moveToFirst()) { name = c.getString(0) ?: name; size = if (c.isNull(1)) -1 else c.getLong(1) }
    }
    if (size > Files.MAX) throw IllegalArgumentException("$name is over the 100 MB limit.")
    val bytes = cr.openInputStream(uri)?.use { input ->
        val out = ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > Files.MAX) throw IllegalArgumentException("$name is over the 100 MB limit.")
        }
        out.toByteArray()
    } ?: return null
    return pendingFrom(name, bytes, cr.getType(uri))
}

/** An attachment ready to send; pictures get a small preview that travels encrypted beside them. */
private fun pendingFrom(name: String, bytes: ByteArray, mime: String?): Pending {
    var thumb: ByteArray? = null
    var w: Int? = null
    var h: Int? = null
    if (Files.sniff(bytes).startsWith("image/")) {
        val o = android.graphics.BitmapFactory.Options().apply { inJustDecodeBounds = true }
        android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size, o)
        if (o.outWidth > 0 && o.outHeight > 0) { w = o.outWidth; h = o.outHeight }
        ChatModel.decode(bytes, 480)?.let { small ->
            val scaled = if (small.width > 480) Bitmap.createScaledBitmap(small, 480, (small.height * 480f / small.width).toInt().coerceAtLeast(1), true) else small
            thumb = ByteArrayOutputStream().also { scaled.compress(Bitmap.CompressFormat.JPEG, 80, it) }.toByteArray()
        }
    }
    return Pending(name, bytes, mime, thumb, w, h)
}
