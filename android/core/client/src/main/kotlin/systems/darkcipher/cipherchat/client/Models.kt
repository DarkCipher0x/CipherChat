package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.Deferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.PublicIdentity
import systems.darkcipher.cipherchat.crypto.long
import systems.darkcipher.cipherchat.crypto.longOrNull
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.wipe
import java.util.concurrent.ConcurrentHashMap

enum class TrustLevel { OK, PENDING, NONE, BAD }

/** One person as this device sees them. [pub] is set only when [trust] is OK. */
data class Person(val user: String, val displayName: String, val owner: Boolean, val fp: String?, val pub: PublicIdentity?, val trust: TrustLevel, val why: String)

/** An encrypted attachment reference, exactly as it travels inside a signed message. */
data class FileRef(val blob: String, val key: String, val sha3: String, val size: Long, val name: String, val mime: String, val kind: String,
                   val thumb: FileRef?, val w: Int?, val h: Int?, val dur: Int?) {
    fun toJson(): JsonObject = buildJsonObject {
        put("blob", blob); put("key", key); put("sha3", sha3); put("size", size)
        if (name.isNotEmpty()) { put("name", name); put("mime", mime); put("kind", kind) }
        thumb?.let { put("thumb", it.toJson()) }
        w?.let { put("w", it) }; h?.let { put("h", it) }; dur?.let { put("dur", it) }
    }

    /** A name safe to show and to save under (no path separators or control characters). */
    val safeName: String get() {
        val s = name.map { if (it.code < 32 || it.code == 127 || it in "/\\:*?\"<>|") '_' else it }.joinToString("")
        return if (s.isEmpty()) "attachment" else s.take(120)
    }

    companion object {
        fun from(f: JsonObject): FileRef = FileRef(f.str("blob"), f.str("key"), f.str("sha3"), f.long("size"),
            f.strOrNull("name") ?: "attachment", f.strOrNull("mime") ?: "application/octet-stream", f.strOrNull("kind") ?: "file",
            (f["thumb"] as? JsonObject)?.let(::from), f.longOrNull("w")?.toInt(), f.longOrNull("h")?.toInt(), f.longOrNull("dur")?.toInt())
    }
}

/** A verified message as every device shows it (reactions and edits applied, newest by server order wins). */
class ChatMessage(
    val id: String, val seq: Long, val from: String,
    /** server time, seconds */
    val at: Long, val mine: Boolean,
    /** text | me | file */
    val kind: String,
    text: String, val replyTo: String?, val files: List<FileRef>,
    /** seconds visible once opened; 0 = not a burn message */
    val burn: Int,
) {
    @Volatile var text: String = text
    var editedSeq: Long = 0
    @Volatile var revealed = false
    @Volatile var burned = false
    internal class Op(val seq: Long, val on: Boolean, val from: String, val emoji: String)
    internal val ops = HashMap<String, Op>()

    /** emoji -> who reacted with it (only current "on" reactions). */
    val reactions: List<Pair<String, List<String>>> get() = synchronized(ops) {
        ops.values.filter { it.on }.groupBy { it.emoji }.map { (e, l) -> e to l.map { it.from } }
    }

    fun myReaction(me: String, emoji: String) = synchronized(ops) { ops["$me|$emoji"]?.on == true }
}

enum class LineKind { SYS, OK, WARN, ERR, SERVER }

/** One row of a room's log: a message, or a line (key changes, server notices, warnings). */
class Entry(
    /** 0 for local lines (shown after everything with a seq) */
    val seq: Long = 0, val at: Long = 0, val message: ChatMessage? = null, val kind: LineKind = LineKind.SYS,
    val who: String = "--", val text: String = "",
    /** A message of yours still on its way to the server (shown until the real one arrives). */
    val outgoing: Outgoing? = null,
)

/** Everything this device knows about one room or direct message. */
class Room internal constructor(val id: String, info: JsonObject) {
    @Volatile var info: JsonObject = info
        internal set
    val kind get() = info.strOrNull("kind") ?: "room"
    val name get() = info.strOrNull("name") ?: ""
    val topic get() = info.strOrNull("topic") ?: ""
    val epoch get() = info.longOrNull("epoch") ?: 0
    val epochAt get() = info.longOrNull("epoch_at") ?: 0
    val needsRotation get() = info.flag("needs_rotation")
    val myRole get() = info.strOrNull("my_role") ?: "member"
    val eligible: List<String> get() = strings(info["eligible"])
    val epochRecipients: List<String> get() = strings(info["epoch_recipients"])
    val members: List<Pair<String, String>> get() =
        (info["members"] as? JsonArray)?.mapNotNull { m -> (m as? JsonObject)?.let { it.str("user") to (it.strOrNull("role") ?: "member") } } ?: emptyList()
    val retentionDays get() = info.longOrNull("retention_days") ?: 0

    @Volatile var unread = 0
        internal set
    @Volatile var loaded = false
        internal set
    @Volatile var moreHistory = false
        internal set
    /** Guarded by itself. */
    val timeline = ArrayList<Entry>()
    fun snapshot(): List<Entry> = synchronized(timeline) { timeline.toList() }

    internal val keys = ConcurrentHashMap<Long, ByteArray>()
    internal val hashes = ConcurrentHashMap<Long, String>()
    internal val headers = ConcurrentHashMap<Long, JsonObject>()
    internal val untrusted: MutableSet<Long> = ConcurrentHashMap.newKeySet()
    internal val seqs = HashSet<Long>()
    internal val msgIds = HashSet<String>()
    internal val epochTried = HashSet<Long>()
    internal val msgs = ConcurrentHashMap<String, ChatMessage>()
    internal class PendingOp(val kind: String, val from: String, val seq: Long, val payload: JsonObject)
    internal val pending = HashMap<String, MutableList<PendingOp>>()
    internal var oldest = Long.MAX_VALUE
    internal val mutex = Mutex()
    internal var loading: Deferred<Unit>? = null
    internal val queue = ArrayList<JsonObject>()

    /** "#name" for rooms, "@other" for direct messages. */
    fun label(me: String) = if (kind == "dm") "@" + (members.map { it.first }.firstOrNull { it != me } ?: "(left)") else "#$name"

    internal fun wipeKeys() {
        synchronized(keys) { for (k in keys.values) wipe(k); keys.clear() }
    }

    private fun strings(e: Any?) = (e as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content } ?: emptyList()
}
