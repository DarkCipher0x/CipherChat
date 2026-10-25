package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.Canon
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.Files
import systems.darkcipher.cipherchat.crypto.Payload
import systems.darkcipher.cipherchat.crypto.arr
import systems.darkcipher.cipherchat.crypto.long
import systems.darkcipher.cipherchat.crypto.longOrNull
import systems.darkcipher.cipherchat.crypto.makeCert
import systems.darkcipher.cipherchat.crypto.safetyNumber
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.unb64
import java.util.concurrent.CopyOnWriteArrayList
import systems.darkcipher.cipherchat.crypto.Room as RoomCrypto

/** What the engine tells the screen. Called on background threads; the UI hops to its own. */
interface ChatListener {
    /** The room list, unread counts or people changed. */
    fun roomsChanged() {}
    fun onlineChanged(online: Boolean) {}
    fun entryAdded(room: Room, entry: Entry) {}
    fun entryChanged(room: Room, entry: Entry) {}
    fun entryRemoved(room: Room, entry: Entry) {}
    /** A line for a room (or none: the current screen). */
    fun notice(room: Room?, kind: LineKind, text: String) {}
}

/**
 * The chat (app.js + messages.js, the Windows ChatEngine; without the screen). Security rules this class keeps:
 *   - nothing is shown as a message unless its hybrid signature verifies under a TRUSTED identity ([Trust]);
 *   - room keys are only accepted from trusted identities, and only handed to trusted identities;
 *   - a room key that went to anyone this device doesn't trust is replaced before the next message is sent;
 *   - keys live in memory only; [lock] wipes them.
 */
class ChatEngine(val api: ChatApi, val me: Me) {
    private val trust = Trust()
    private val rooms = LinkedHashMap<String, Room>()
    private val gate = Any()
    internal val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pollJob: Job? = null
    @Volatile private var lastSeq = 0L
    @Volatile private var rev = 0L
    @Volatile private var sig = 0L
    @Volatile private var autoBusy = false
    private val listeners = CopyOnWriteArrayList<ChatListener>()

    @Volatile var state: JsonObject = JsonObject(emptyMap()); private set
    @Volatile var people: Map<String, Person> = emptyMap(); private set
    @Volatile var ownerProblem = ""; private set
    @Volatile var online = false; private set
    val myUser: String get() = me.user
    /** Voice and video calls: signals, keys and ringing. */
    val calls: Calls by lazy { Calls(this) }
    val iAmOwner get() = (state["me"] as? JsonObject)?.flag("owner") == true
    val canCreateRooms get() = (state["me"] as? JsonObject)?.flag("can_create") == true
    val retentionChoices: List<Long> get() =
        ((state["limits"] as? JsonObject)?.get("retention") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.longOrNull } ?: listOf(0L)

    /** The room on screen while the app is in front: new messages there don't count as unread. */
    @Volatile var viewing: Room? = null

    fun addListener(l: ChatListener) = listeners.add(l)
    fun removeListener(l: ChatListener) = listeners.remove(l)
    private inline fun emit(f: (ChatListener) -> Unit) { for (l in listeners) try { f(l) } catch (e: RuntimeException) { } }

    fun markRead(r: Room) {
        if (r.unread == 0) return
        r.unread = 0
        emit { it.roomsChanged() }
    }

    val roomList: List<Room> get() = synchronized(gate) { rooms.values.toList() }
    fun roomById(id: String): Room? = synchronized(gate) { rooms[id] }

    // ------------------------------------------------------------------------------------------- state
    suspend fun start() {
        refresh()
        lastSeq = state.longOrNull("last_seq") ?: 0
        rev = state.longOrNull("dir_rev") ?: 0
        online = true
        emit { it.onlineChanged(true) }
        if (me.anchorFp == null) say(null, LineKind.WARN, "You haven't verified the owner yet, so nobody can be trusted. Compare safety numbers to pin the owner's identity.")
        pollJob = scope.launch { pollLoop() }
        outbox.start(scope)
    }

    suspend fun refresh() = applyState(api.call("state"))

    private fun applyState(st: JsonObject) {
        state = st
        val t = trust.evaluate(st.arr("directory"), st.str("owner"), me.anchorFp)
        people = t.people
        if (t.ownerProblem.isNotEmpty() && ownerProblem != t.ownerProblem && me.anchorFp != null) say(null, LineKind.WARN, "Trust problem: " + t.ownerProblem + ".")
        ownerProblem = t.ownerProblem
        synchronized(gate) {
            val seen = HashSet<String>()
            for (info in st.arr("rooms").filterIsInstance<JsonObject>()) {
                val id = info.str("id")
                seen.add(id)
                val r = rooms[id]
                if (r != null) r.info = info else rooms[id] = Room(id, info)
            }
            for (id in rooms.keys.filter { it !in seen }) { rooms.remove(id)?.wipeKeys() }
        }
        emit { it.roomsChanged() }
    }

    internal fun trusted(user: String): Person? = people[user]?.takeIf { it.trust == TrustLevel.OK && it.pub != null }

    private fun say(r: Room?, k: LineKind, text: String) {
        if (r == null) { emit { it.notice(null, k, text) }; return }
        add(r, Entry(at = System.currentTimeMillis() / 1000, kind = k, who = if (k == LineKind.ERR) "!!" else "--", text = text))
    }

    private fun add(r: Room, e: Entry) {
        synchronized(r.timeline) {
            if (e.seq == 0L) r.timeline.add(e)
            else {
                val i = r.timeline.indexOfFirst { it.seq == 0L || it.seq > e.seq }
                if (i < 0) r.timeline.add(e) else r.timeline.add(i, e)
            }
        }
        emit { it.entryAdded(r, e) }
    }

    // ------------------------------------------------------------------------------------------- rooms
    /** Loads a room's keys and recent history (once); later items arrive through polling. */
    suspend fun openRoom(r: Room) {
        r.unread = 0
        emit { it.roomsChanged() }
        val job = synchronized(r) { r.loading ?: scope.async(start = CoroutineStart.LAZY) { loadRoom(r) }.also { r.loading = it } }
        job.await()
    }

    private suspend fun loadRoom(r: Room) {
        try {
            loadEpochs(r)
            val res = api.call("rooms/" + r.id + "/items")
            r.moreHistory = res.flag("more")
            for (it in res.arr("items").filterIsInstance<JsonObject>()) handle(r, it, live = false)
            r.loaded = true
            val q = synchronized(r.queue) { r.queue.toList().also { r.queue.clear() } }
            for (it in q) handle(r, it, live = true)
            if (res.arr("items").isEmpty()) say(r, LineKind.SYS, "Nothing here yet. Messages are end-to-end encrypted with this room's key; the server only stores ciphertext.")
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            if (e !is ApiException && e !is CryptoFail) throw e
            say(r, LineKind.ERR, "Couldn't load this room: " + e.message)
            synchronized(r) { r.loading = null }
        }
    }

    suspend fun loadOlder(r: Room) {
        val res = api.call("rooms/" + r.id + "/items?before=" + r.oldest)
        for (it in res.arr("items").filterIsInstance<JsonObject>().reversed()) handle(r, it, live = false)
        r.moreHistory = res.flag("more")
    }

    private suspend fun loadEpochs(r: Room) {
        val res = api.call("rooms/" + r.id + "/epochs")
        for (it in res.arr("items").filterIsInstance<JsonObject>()) openEpochItem(r, it, announce = false)
    }

    /**
     * Accept a room key only if a trusted identity signed it, it was made for MY current identity, and its commitment
     * matches. Note anyone it went to whom this device doesn't trust: that key won't be used to send.
     */
    private fun openEpochItem(r: Room, it: JsonObject, announce: Boolean): Boolean {
        val epoch = it.long("epoch")
        if (r.keys.containsKey(epoch)) return true
        val from = it.str("from")
        val signer = trusted(from)
        if (signer == null) { if (announce) say(r, LineKind.WARN, "Ignored room key #$epoch from $from: that identity isn't verified."); return false }
        val body = it.obj("body")
        val w = body.strOrNull("w") ?: return false
        return try {
            val o = RoomCrypto.openEpoch(me.id, me.fp, r.id, epoch, from, body.str("h"), body.str("s"), w, signer.pub!!)
            r.keys[epoch] = o.key
            r.hashes[epoch] = RoomCrypto.headerHash(o.raw)
            r.headers[epoch] = o.header
            val odd = o.header.arr("recipients").filterIsInstance<JsonObject>()
                .filter { x -> trusted(x.str("u"))?.fp != x.str("fp") }.map { x -> x.str("u") }
            if (odd.isNotEmpty()) {
                r.untrusted.add(epoch)
                say(r, LineKind.WARN, "Room key #$epoch was also given to identities you can't verify: " + odd.joinToString(", ") + ". It will be replaced before you send.")
            }
            val prev = r.hashes[epoch - 1]
            if (epoch > 1 && prev != null && o.header.strOrNull("prev") != prev)
                say(r, LineKind.WARN, "Room key #$epoch doesn't follow on from key #${epoch - 1} (key history was altered).")
            true
        } catch (e: CryptoFail) {
            if (announce) say(r, LineKind.ERR, "Room key #$epoch from $from was refused: " + e.message)
            false
        }
    }

    private suspend fun handle(r: Room, it: JsonObject, live: Boolean) {
        r.mutex.withLock {
            try { handleLocked(r, it, live) }
            catch (e: CancellationException) { throw e }
            catch (e: Exception) {
                if (e !is CryptoFail && e !is ApiException && e !is IllegalStateException && e !is NumberFormatException) throw e
                say(r, LineKind.ERR, "Internal error: " + e.message)
            }
        }
    }

    private suspend fun handleLocked(r: Room, it: JsonObject, live: Boolean) {
        val seq = it.long("seq")
        if (!r.seqs.add(seq)) return
        r.oldest = minOf(r.oldest, seq)
        val kind = it.str("kind")
        val from = it.strOrNull("from") ?: "?"
        val at = it.longOrNull("at") ?: 0
        fun line(k: LineKind, who: String, text: String) = Entry(seq = seq, at = at, kind = k, who = who, text = text)
        when (kind) {
            "msg" -> {
                val epoch = it.long("epoch")
                if (!r.keys.containsKey(epoch) && r.epochTried.add(epoch)) {
                    try { loadEpochs(r) } catch (e: ApiException) { }
                }
                val who = trusted(from)
                val key = r.keys[epoch]
                if (key == null) { add(r, line(LineKind.WARN, from, "[encrypted with room key #$epoch, which wasn't made for you]")); return }
                if (who == null) { add(r, line(LineKind.WARN, from, "[hidden: $from's identity isn't verified]")); return }
                val m = try {
                    val b = it.obj("body")
                    RoomCrypto.openMessage(r.id, epoch, from, b.str("h"), b.str("c"), b.str("s"), key, who.pub!!)
                } catch (e: CryptoFail) { add(r, line(LineKind.ERR, from, "[refused: " + e.message + "]")); return }
                // signed message ids are unique: a second copy is the server replaying an old message
                if (!r.msgIds.add(m.id)) { add(r, line(LineKind.WARN, from, "[ignored: replayed copy of an earlier message]")); return }
                val shown = show(r, seq, from, at, m)
                if (shown && live && from != myUser && r !== viewing) { r.unread++; emit { l -> l.roomsChanged() } }
            }
            "epoch" -> {
                val got = openEpochItem(r, it, live)
                val epoch = it.long("epoch")
                val h = r.headers[epoch]
                val recips = if (got && h != null) h.arr("recipients").filterIsInstance<JsonObject>().joinToString(", ") { x -> x.str("u") } else ""
                add(r, line(LineKind.SYS, "--", if (got) "new room key #$epoch from $from for $recips (signed, ML-KEM-1024 + X25519)"
                    else "room key #$epoch from $from" + if (it.obj("body").strOrNull("w") != null) " (not accepted)" else " (not for you)"))
            }
            "event" -> add(r, line(LineKind.SERVER, "server", describe(it.obj("body"))))
            "redact" -> {
                val t = it.obj("body")["target"] as? JsonPrimitive ?: return
                val target = t.content.toLong()
                // the server deletes a burn message once everyone has opened it; one still being read here waits for its countdown
                val e = synchronized(r.timeline) { r.timeline.firstOrNull { x -> x.seq == target } }
                val m = e?.message
                if (m != null && m.burn > 0 && m.revealed && !m.mine && !m.burned) return
                remove(r, target)
            }
        }
    }

    private fun remove(r: Room, seq: Long) {
        val e = synchronized(r.timeline) { r.timeline.firstOrNull { it.seq == seq }?.also { r.timeline.remove(it) } } ?: return
        e.message?.let { r.msgs.remove(it.id) }
        emit { it.entryRemoved(r, e) }
    }

    private fun describe(b: JsonObject): String {
        fun list(k: String) = (b[k] as? JsonArray)?.joinToString(", ") { (it as? JsonPrimitive)?.content ?: "?" } ?: ""
        val by = b.strOrNull("by") ?: "?"
        return when (b.strOrNull("e")) {
            "created" -> by + " created " + (b.strOrNull("name")?.takeIf { it.isNotEmpty() }?.let { "#$it" } ?: "this conversation") +
                (list("members").takeIf { it.isNotEmpty() }?.let { " with $it" } ?: "")
            "members" -> listOf(list("add").let { if (it.isNotEmpty()) "$by added $it" else "" }, list("remove").let { if (it.isNotEmpty()) "$by removed $it" else "" },
                list("admin").let { if (it.isNotEmpty()) "$by made $it admin" else "" }, list("member").let { if (it.isNotEmpty()) "$by made $it a member" else "" })
                .filter { it.isNotEmpty() }.joinToString("; ")
            "updated" -> by + " changed " + b.entries.filter { it.key != "e" && it.key != "by" }.joinToString(", ") { it.key.replace('_', ' ') + " to " + it.value.toString() }
            "left" -> "$by left"
            "call" -> by + " started a " + (if (b.strOrNull("media") == "video") "video" else "voice") + " call"
            else -> by + ": " + b.strOrNull("e")
        }
    }

    // ------------------------------------------------------------------------------------------- messages, reactions, edits
    private fun show(r: Room, seq: Long, from: String, at: Long, opened: RoomCrypto.OpenedMsg): Boolean {
        val p = opened.payload
        val kind = p.strOrNull("k") ?: "text"
        if (kind == "react" || kind == "edit") {
            val target = p.str("target")
            val tm = r.msgs[target]
            if (tm != null) apply(r, tm, kind, from, seq, p)
            else r.pending.getOrPut(target) { ArrayList() }.add(Room.PendingOp(kind, from, seq, p))
            return false                                                       // nothing new to show in the log
        }
        val m = ChatMessage(opened.id, seq, from, at, from == myUser, kind, p.str("text"), p.strOrNull("re"),
            (p["files"] as? JsonArray)?.filterIsInstance<JsonObject>()?.map(FileRef::from) ?: emptyList(), (p.longOrNull("burn") ?: 0).toInt())
        r.msgs[m.id] = m
        add(r, Entry(seq = seq, at = at, message = m, who = from))
        if (m.mine) outbox.delivered(m.id)                                       // its "sending" placeholder goes
        if (m.burn == 0) r.pending.remove(m.id)?.forEach { o -> apply(r, m, o.kind, o.from, o.seq, o.payload) }
        return true
    }

    /** The newest operation (by server order) for each person+emoji wins; edits only from the author. */
    private fun apply(r: Room, m: ChatMessage, kind: String, from: String, seq: Long, p: JsonObject) {
        if (m.burn > 0) return                                                 // no reactions or edits on burn messages
        if (kind == "edit") {
            if (from != m.from || seq <= m.editedSeq) return
            m.editedSeq = seq
            m.text = p.str("text")
        } else {
            val emoji = p.str("emoji")
            val k = "$from|$emoji"
            synchronized(m.ops) {
                val prev = m.ops[k]
                if (prev != null && prev.seq >= seq) return
                m.ops[k] = ChatMessage.Op(seq, (p["on"] as? JsonPrimitive)?.content == "true", from, emoji)
            }
        }
        val e = synchronized(r.timeline) { r.timeline.firstOrNull { it.message === m } } ?: return
        emit { it.entryChanged(r, e) }
    }

    fun messageById(r: Room, id: String): ChatMessage? = r.msgs[id]

    // ------------------------------------------------------------------------------------------- room keys and sending
    private suspend fun rotate(r: Room, reason: String): ByteArray {
        repeat(3) {
            val recips = r.eligible.map { u ->
                val p = trusted(u) ?: throw IllegalStateException("Can't give $u the room key: " + (people[u]?.why ?: "no verified identity") + ".")
                RoomCrypto.Recipient(u, p.fp!!, p.pub!!)
            }
            if (recips.none { it.u == myUser }) throw IllegalStateException("Your identity isn't certified yet, so you can't hold this room's key.")
            val built = withContext(Dispatchers.Default) { RoomCrypto.buildEpoch(me.id, me.fp, r.id, r.epoch + 1, recips, r.hashes[r.epoch] ?: "") }
            try {
                val res = api.call("rooms/" + r.id + "/epoch", buildJsonObject {
                    put("pkg", buildJsonObject {
                        put("h", built.pkg.h); put("s", built.pkg.s)
                        put("w", buildJsonObject { for ((u, v) in built.pkg.w) put(u, v) })
                    })
                })
                val epoch = res.long("epoch")
                r.keys[epoch] = built.key
                val raw = unb64(built.pkg.h)
                r.hashes[epoch] = RoomCrypto.headerHash(raw)
                r.headers[epoch] = Canon.parseSigned(built.pkg.h, 65536).obj
                say(r, LineKind.SYS, "Made room key #$epoch for " + recips.joinToString(", ") { it.u } + " ($reason).")
                refresh()
                return built.key
            } catch (e: ApiException) {
                if (!e.flag("stale")) throw e
                refresh()
                val k = r.keys[r.epoch]
                if (!r.needsRotation && k != null) return k
            }
        }
        throw IllegalStateException("The room kept changing while making a new key. Try again.")
    }

    private suspend fun keyFor(r: Room): ByteArray {
        if (me.anchorFp == null) throw IllegalStateException("Verify the owner first.")
        if (!r.needsRotation && r.epoch > 0 && !r.keys.containsKey(r.epoch)) loadEpochs(r)
        val stale = r.epoch > 0 && System.currentTimeMillis() / 1000 - r.epochAt > ROTATE_AFTER_S
        val key = r.keys[r.epoch]
        if (!r.needsRotation && r.epoch > 0 && key != null && r.epoch !in r.untrusted && !stale) return key
        val why = when {
            r.epoch == 0L -> "first key"
            r.needsRotation -> "members changed"
            r.epoch in r.untrusted -> "replacing a key given to unverified identities"
            stale -> "weekly renewal"
            else -> "you didn't hold the current key"
        }
        return rotate(r, why)
    }

    /** Admins renew keys as soon as members change, so newcomers can read without waiting for someone to speak. */
    suspend fun maybeAutoRotate(r: Room) {
        if (autoBusy || me.anchorFp == null || !r.needsRotation) return
        val admin = r.kind == "dm" || r.myRole == "admin"
        if (!admin || myUser !in r.eligible || !r.eligible.all { trusted(it) != null }) return
        autoBusy = true
        try { rotate(r, "members changed") }
        catch (e: ApiException) { }                                            // the next send retries and reports
        catch (e: IllegalStateException) { }
        finally { autoBusy = false }
    }

    // ------------------------------------------------------------------------------------------- the outbox
    private val outbox = Outbox(this)

    /** Messages still on their way (queued, sending, or failed with a reason). */
    val outgoing: List<Outgoing> get() = outbox.pending

    fun retry(o: Outgoing) = outbox.retry(o)
    fun discard(o: Outgoing) = outbox.discard(o)
    /** Try queued messages now (the app calls this when the network comes back). */
    fun networkChanged() = outbox.wake()
    /** Text messages still waiting, sealed where they already were, for the app's vault across a lock. */
    fun outboxSnapshot(): List<JsonObject> = outbox.snapshot()
    val outboxDroppedOnLock: Int get() = outbox.droppedOnLock
    /** Put messages saved by [outboxSnapshot] back in the queue (after [start]). */
    fun restoreOutbox(saved: List<JsonObject>) = outbox.restore(saved)

    /** Queues any payload kind: it's sealed and sent by the outbox, in order, through dropped connections. */
    private fun enqueue(r: Room, kind: String, preview: String, payload: JsonObject, files: List<OutgoingFile> = emptyList()) {
        Payload.check(if (files.isEmpty()) payload else JsonObject(payload + ("files" to buildJsonArray { add(placeholderRef) })))
        if (Canon.bytes(payload).size > RoomCrypto.MAX_TEXT_BYTES - 600 * files.size)
            throw IllegalArgumentException("That message is too long (${RoomCrypto.MAX_TEXT_BYTES} bytes at most).")
        if (me.anchorFp == null) throw IllegalStateException("Verify the owner first.")
        val o = Outgoing(r, kind, preview, payload, files)
        outgoingAdded(o)
        outbox.add(o)
    }

    internal suspend fun seal(r: Room, payload: JsonObject): RoomCrypto.SealedMsg {
        if (Canon.bytes(payload).size > RoomCrypto.MAX_TEXT_BYTES) throw IllegalArgumentException("That message is too long (${RoomCrypto.MAX_TEXT_BYTES} bytes at most).")
        val key = keyFor(r)
        return withContext(Dispatchers.Default) { RoomCrypto.sealMessage(me.id, me.fp, r.id, r.epoch, key, payload) }
    }

    internal fun outgoingAdded(o: Outgoing) {
        if (!o.visible) return
        val e = Entry(at = System.currentTimeMillis() / 1000, who = myUser, outgoing = o)
        o.entry = e
        add(o.room, e)
    }

    internal fun outgoingChanged(o: Outgoing) {
        val e = o.entry ?: return
        emit { it.entryChanged(o.room, e) }
    }

    internal fun outgoingGone(o: Outgoing) {
        val e = o.entry ?: return
        o.entry = null
        synchronized(o.room.timeline) { o.room.timeline.remove(e) }
        emit { it.entryRemoved(o.room, e) }
    }

    private fun payload(vararg kv: Pair<String, Any?>): JsonObject = buildJsonObject {
        for ((k, v) in kv) when (v) {
            null -> {}
            is String -> put(k, v)
            is Int -> put(k, v)
            is Boolean -> put(k, v)
            is JsonElement -> put(k, v)
            else -> throw IllegalArgumentException(k)
        }
    }

    /** Queues a message; it's sent as soon as the server can be reached (see [outgoing]). */
    fun sendText(r: Room, text: String, replyTo: String? = null, burn: Int = 0, action: Boolean = false) =
        enqueue(r, if (action) "me" else "text", text, payload("k" to if (action) "me" else "text", "text" to text, "re" to replyTo, "burn" to burn.takeIf { it > 0 }))

    fun react(r: Room, m: ChatMessage, emoji: String, on: Boolean) =
        enqueue(r, "react", emoji, payload("k" to "react", "text" to "", "target" to m.id, "emoji" to emoji, "on" to on))

    fun edit(r: Room, m: ChatMessage, text: String) {
        if (!m.mine) throw IllegalStateException("You can only edit your own messages.")
        enqueue(r, "edit", text, payload("k" to "edit", "text" to text, "target" to m.id))
    }

    suspend fun redact(r: Room, seq: Long) { api.call("rooms/" + r.id + "/redact", buildJsonObject { put("seq", seq) }) }

    /** The person opened a burn message: tell the server (it destroys the ciphertext once everyone has). */
    suspend fun revealBurn(r: Room, m: ChatMessage) {
        if (m.burn == 0 || m.revealed) return
        m.revealed = true
        if (!m.mine) {
            try { api.call("rooms/" + r.id + "/burn", buildJsonObject { put("seq", m.seq) }) }
            catch (e: ApiException) { say(r, LineKind.ERR, "Couldn't tell the server to burn it: " + e.message) }
        }
    }

    /** The countdown ended: wipe the text and drop the message from this device. */
    fun burnOut(r: Room, m: ChatMessage) {
        m.text = ""
        m.burned = true
        remove(r, m.seq)
    }

    // ------------------------------------------------------------------------------------------- attachments
    class OutgoingFile(val name: String, val bytes: ByteArray, val mime: String? = null, val thumb: ByteArray? = null,
                       val w: Int? = null, val h: Int? = null, val dur: Int? = null)

    private suspend fun sealAndUpload(r: Room, bytes: ByteArray, progress: ((Long, Long) -> Unit)?): FileRef {
        val s = withContext(Dispatchers.Default) { Files.seal(bytes) }
        val res = api.upload(r.id, s.data, progress)
        if (res.strOrNull("sha3") != s.sha3 || res.longOrNull("size") != s.data.size.toLong())
            throw IllegalStateException("The server stored something other than what was sent. Not sending.")
        return FileRef(res.str("id"), s.key, s.sha3, s.size, "", "", "", null, null, null, null)
    }

    /** Queues files (1-10, 100 MB each) with a caption; each is encrypted and uploaded once, then the message is sent. */
    fun sendFiles(r: Room, caption: String, files: List<OutgoingFile>, replyTo: String? = null, burn: Int = 0) {
        if (files.isEmpty() || files.size > 10) throw IllegalArgumentException("Attach 1 to 10 files per message.")
        files.firstOrNull { it.bytes.size > Files.MAX }?.let { throw IllegalArgumentException(it.name + " is over the 100 MB limit.") }
        val preview = (if (caption.isNotEmpty()) "$caption\n" else "") + files.joinToString(", ") { "📎 " + it.name }
        enqueue(r, "file", preview, payload("k" to "file", "text" to caption, "re" to replyTo, "burn" to burn.takeIf { it > 0 }), files)
    }

    /** One attachment (and its preview picture) encrypted and uploaded: its ref for the message and the blob ids. */
    internal suspend fun uploadFile(r: Room, f: OutgoingFile): Pair<JsonObject, List<String>> {
        val sniff = Files.sniff(f.bytes)
        val kind = when {
            sniff.startsWith("image/") -> "image"
            sniff.startsWith("video/") -> "video"
            (f.mime ?: "").startsWith("audio/") -> "audio"
            else -> "file"
        }
        val mime = if (kind == "image" || kind == "video") sniff else (f.mime ?: "application/octet-stream").take(100)
        val main = sealAndUpload(r, f.bytes, null)
        val blobs = arrayListOf(main.blob)
        var thumb: FileRef? = null
        if (f.thumb != null && (kind == "image" || kind == "video")) {
            thumb = sealAndUpload(r, f.thumb, null)
            blobs.add(thumb.blob)
        }
        return main.copy(name = f.name.take(200), mime = mime, kind = kind, thumb = thumb, w = f.w, h = f.h, dur = f.dur).toJson() to blobs
    }

    private val placeholderRef = buildJsonObject {
        put("blob", "0".repeat(24)); put("key", "A".repeat(43) + "="); put("sha3", "0".repeat(64)); put("size", 0)
        put("name", "x"); put("mime", "x"); put("kind", "file")
    }

    /** Downloads and decrypts an attachment (checks its signed hash and every chunk). */
    suspend fun fetchFile(r: Room, f: FileRef): ByteArray {
        val sealed = api.download(r.id, f.blob, f.size)
        return withContext(Dispatchers.Default) { Files.open(sealed, f.key, f.size, f.sha3) }
    }

    // ------------------------------------------------------------------------------------------- rooms, people, devices
    private fun strings(l: List<String>) = buildJsonArray { for (x in l) add(JsonPrimitive(x)) }

    suspend fun createRoom(name: String, topic: String, retentionDays: Long, members: List<String>): Room {
        val res = api.call("rooms", buildJsonObject {
            put("name", name.trimStart('#')); put("topic", topic); put("retention_days", retentionDays); put("members", strings(members))
        })
        refresh()
        return roomById(res.str("id")) ?: throw IllegalStateException("The new room didn't appear.")
    }

    suspend fun openDm(user: String): Room {
        val res = api.call("dm", buildJsonObject { put("user", user) })
        refresh()
        return roomById(res.str("id")) ?: throw IllegalStateException("The conversation didn't appear.")
    }

    suspend fun changeMembers(r: Room, add: List<String>, remove: List<String>) {
        api.call("rooms/" + r.id + "/members", buildJsonObject { put("add", strings(add)); put("remove", strings(remove)) })
        refresh()
        maybeAutoRotate(r)
    }

    suspend fun updateRoom(r: Room, name: String, topic: String, retentionDays: Long) {
        api.call("rooms/" + r.id + "/update", buildJsonObject { put("name", name.trimStart('#')); put("topic", topic); put("retention_days", retentionDays) })
        refresh()
    }

    suspend fun leave(r: Room) { api.call("rooms/" + r.id + "/leave", JsonObject(emptyMap())); refresh() }
    suspend fun deleteRoom(r: Room) { api.call("rooms/" + r.id + "/delete", JsonObject(emptyMap())); refresh() }
    suspend fun rotateNow(r: Room) { rotate(r, "by request") }

    fun safetyNumber(p: Person): String = p.fp?.let { safetyNumber(me.fp, it) } ?: ""

    /** Owner only: certify someone after comparing the safety number out of band. */
    suspend fun certify(p: Person) {
        val fp = p.fp ?: throw IllegalStateException(p.user + " hasn't set up the chat yet.")
        val cert = makeCert(me.id, me.fp, p.user, fp, System.currentTimeMillis())
        api.call("certify", buildJsonObject { put("user", p.user); put("cert", buildJsonObject { put("b", cert.b); put("s", cert.s) }) })
        refresh()
    }

    suspend fun revoke(p: Person) { api.call("revoke", buildJsonObject { put("user", p.user) }); refresh() }

    suspend fun devices(): JsonObject = api.call("devices")

    /** Pairs another app (needs a fresh code); returns the one-time pairing code to show. */
    suspend fun pairDevice(name: String): String {
        val j = api.call("devices", buildJsonObject { put("name", name) })
        return Pairing.format(api.origin, j.str("token"))
    }

    suspend fun revokeDevice(id: String) { api.call("devices/$id/revoke", JsonObject(emptyMap())) }

    // ------------------------------------------------------------------------------------------- polling and locking
    private suspend fun pollLoop() {
        var backoff = 1000L
        while (scope.isActive) {
            try {
                val res = api.poll(lastSeq, rev, sig)
                val signals = res["signals"] as? JsonArray
                if (signals != null && signals.isNotEmpty()) {
                    sig = maxOf(sig, signals.filterIsInstance<JsonObject>().maxOf { it.longOrNull("sid") ?: 0 })
                    calls.onSignals(signals)
                }
                if (!online) { online = true; emit { it.onlineChanged(true) }; outbox.wake() }      // queued messages go now
                backoff = 1000L
                val nrev = res.longOrNull("dir_rev") ?: rev
                if (nrev != rev) { rev = nrev; refresh() }
                for (it in res.arr("items").filterIsInstance<JsonObject>()) {
                    val r = roomById(it.str("room")) ?: continue
                    if (!r.loaded) {
                        if (synchronized(r) { r.loading != null }) synchronized(r.queue) { r.queue.add(it) }
                        else if (it.strOrNull("kind") == "msg") { r.unread++; emit { l -> l.roomsChanged() } }
                        continue
                    }
                    handle(r, it, live = true)
                }
                lastSeq = maxOf(lastSeq, res.longOrNull("last_seq") ?: lastSeq)
            } catch (e: CancellationException) { throw e }
            catch (e: ApiException) {
                if (e.denied) { say(null, LineKind.ERR, "Your chat access was removed."); break }
                backoff = offline(backoff)
            } catch (e: Exception) {
                if (e !is CryptoFail && e !is IllegalStateException && e !is java.io.IOException) throw e
                backoff = offline(backoff)
            }
        }
    }

    private suspend fun offline(backoff: Long): Long {
        if (online) { online = false; emit { it.onlineChanged(false) } }
        delay(backoff)
        return minOf(30_000L, backoff * 2)
    }

    /** Stops polling and wipes every room key from memory. The engine can't be used afterwards. */
    fun lock() {
        scope.cancel()
        synchronized(gate) {
            for (r in rooms.values) r.wipeKeys()
            rooms.clear()
        }
        me.id.destroy()
    }

    companion object { private const val ROTATE_AFTER_S = 7L * 86400 }
}
