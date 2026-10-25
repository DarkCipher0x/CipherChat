package systems.darkcipher.cipherchat.chat

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import systems.darkcipher.cipherchat.client.ChatEngine
import systems.darkcipher.cipherchat.client.ChatListener
import systems.darkcipher.cipherchat.client.Entry
import systems.darkcipher.cipherchat.client.FileRef
import systems.darkcipher.cipherchat.client.LineKind
import systems.darkcipher.cipherchat.client.Room
import systems.darkcipher.cipherchat.designsystem.DcxPrompts

/** What the chat needs from the app around it. */
interface ChatHost {
    val prompts: DcxPrompts
    val version: String
    var autoLockMinutes: Int
    /** Signed in with a paired-device token: the server lets only a password or passkey sign-in pair more devices. */
    val pairedDevice: Boolean
    fun startCall(room: Room, media: String, people: List<String>)
    /** Whether incoming calls may ring over the lock screen (Android 14+ asks the person). */
    val fullScreenCalls: Boolean
    fun allowFullScreenCalls()
    /** Wipes the chat keys (the phone stays paired). */
    fun lock()
    suspend fun signOut(forgetPhone: Boolean)
    /** The room on screen changed (for notifications). */
    fun viewing(room: Room?)
}

/**
 * The engine's events as Compose state: [rev] ticks whenever the room list or people change, [timeline] mirrors the
 * open room's log. Engine callbacks arrive on background threads and are moved to the main thread here.
 */
class ChatModel(val engine: ChatEngine, val host: ChatHost) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    var rev by mutableIntStateOf(0); private set
    var online by mutableStateOf(engine.online); private set
    var room by mutableStateOf<Room?>(null); private set
    val timeline = mutableStateListOf<Entry>()
    var entryRev by mutableIntStateOf(0); private set
    /** A line shown above the room list (owner problems, access removed...). */
    var banner by mutableStateOf<Pair<LineKind, String>?>(null)
    var status by mutableStateOf<String?>(null)

    /** GIFs of this session (sent, or played in a room), newest first, so sending one again is one tap. Memory only:
     *  gone when the phone locks the chat. A burn message's GIF is never kept. */
    val gifs = mutableStateListOf<Pair<String, ByteArray>>()

    fun rememberGif(name: String, bytes: ByteArray) {
        gifs.removeAll { it.first == name && it.second.size == bytes.size }
        gifs.add(0, name to bytes)
        while (gifs.size > 30 || (gifs.size > 1 && gifs.sumOf { it.second.size.toLong() } > 96L * 1024 * 1024)) gifs.removeAt(gifs.size - 1)
    }
    private val thumbs = object : LruCache<String, Bitmap>(24 * 1024 * 1024) {
        override fun sizeOf(key: String, value: Bitmap) = value.byteCount
    }

    private val listener = object : ChatListener {
        override fun roomsChanged() { scope.launch { rev++ } }
        override fun onlineChanged(online: Boolean) { scope.launch { this@ChatModel.online = online } }
        override fun entryAdded(room: Room, entry: Entry) { scope.launch { if (room === this@ChatModel.room) resync() } }
        override fun entryChanged(room: Room, entry: Entry) { scope.launch { if (room === this@ChatModel.room) entryRev++ } }
        override fun entryRemoved(room: Room, entry: Entry) { scope.launch { if (room === this@ChatModel.room) timeline.remove(entry) } }
        override fun notice(room: Room?, kind: LineKind, text: String) { scope.launch { banner = kind to text } }
    }

    init { engine.addListener(listener) }

    private fun resync() {
        val r = room ?: return
        val now = r.snapshot()
        if (now.size == timeline.size + 1 && now.subList(0, timeline.size) == timeline.toList()) timeline.add(now.last())
        else { timeline.clear(); timeline.addAll(now) }
    }

    fun open(r: Room?) {
        room = r
        engine.viewing = r
        host.viewing(r)
        timeline.clear()
        if (r == null) return
        timeline.addAll(r.snapshot())
        scope.launch {
            try { withContext(Dispatchers.Default) { engine.openRoom(r) } } catch (e: Exception) { banner = LineKind.ERR to (e.message ?: "Couldn't open the room") }
            if (room === r) { resync(); engine.markRead(r) }
        }
    }

    /** Runs [block] off the main thread, showing its error (and an optional status while it runs). */
    fun run(what: String? = null, block: suspend () -> Unit) {
        scope.launch {
            if (what != null) status = what
            try { withContext(Dispatchers.Default) { block() } }          // signing and verifying stay off the main thread
            catch (e: kotlinx.coroutines.CancellationException) { throw e }
            catch (e: Exception) { banner = LineKind.ERR to (e.message ?: "That didn't work.") }
            finally { if (what != null) status = null }
        }
    }

    suspend fun thumb(r: Room, f: FileRef, px: Int): Bitmap? {
        thumbs.get(f.blob)?.let { return it }
        val bytes = engine.fetchFile(r, f)
        val bmp = withContext(Dispatchers.Default) { decode(bytes, px) } ?: return null
        thumbs.put(f.blob, bmp)
        return bmp
    }

    fun dispose() {
        engine.removeListener(listener)
        engine.viewing = null
        thumbs.evictAll()
        scope.cancel()
    }

    companion object {
        /** Decodes an image no wider than [px] (attachments are checked, but images are still untrusted input). */
        fun decode(bytes: ByteArray, px: Int): Bitmap? {
            val o = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, o)
            if (o.outWidth <= 0 || o.outHeight <= 0 || o.outWidth.toLong() * o.outHeight > 100_000_000L) return null
            var s = 1
            while (o.outWidth / (s * 2) >= px) s *= 2
            return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = s })
        }

        fun human(n: Long): String = when {
            n < 1024 -> "$n B"
            n < 1048576 -> "%.1f KB".format(n / 1024.0)
            else -> "%.1f MB".format(n / 1048576.0)
        }
    }
}
