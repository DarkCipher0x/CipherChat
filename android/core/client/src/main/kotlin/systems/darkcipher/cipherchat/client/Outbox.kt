package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.Canon
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.Room as RoomCrypto

/**
 * A message on its way to the server. It survives bad networks: it is sealed once and resent unchanged until the
 * server has it (the server recognises a resend by its signed message id, so a send whose answer was lost never turns
 * into two messages), and it is only re-sealed when the server says the room key changed and it hasn't got it.
 */
class Outgoing internal constructor(
    val room: Room,
    /** text | me | file | react | edit */
    val kind: String,
    /** What the timeline shows while it waits (the text, or the caption and file names). */
    val preview: String,
    internal val base: JsonObject,
    internal val files: List<ChatEngine.OutgoingFile>,
) {
    enum class State { QUEUED, SENDING, SENT, FAILED }

    @Volatile var state = State.QUEUED; internal set
    /** Why it failed (a refusal that retrying can't fix), or what's happening while it waits. */
    @Volatile var note: String? = null; internal set
    @Volatile var attempts = 0; internal set
    internal var entry: Entry? = null
    internal val uploaded = ArrayList<JsonObject>()          // file refs already on the server (an upload isn't repeated)
    internal val blobs = ArrayList<String>()
    internal var sealed: RoomCrypto.SealedMsg? = null
    internal var msgId: String? = null
    val visible get() = kind == "text" || kind == "me" || kind == "file"
}

/**
 * The engine's outbox: one worker sends queued messages in order. Offline, timeouts, server errors and rate limits
 * are waited out (1 s doubling to 30 s, and at once when the connection comes back); a refusal that retrying can't fix
 * marks the message failed, with Retry and Discard. Nothing here is written to disk by the engine: the app may save
 * [snapshot] (sealed messages only) in its vault when it locks and give it back to [restore].
 */
internal class Outbox(private val e: ChatEngine) {
    private val items = ArrayList<Outgoing>()
    private val kick = Channel<Unit>(Channel.CONFLATED)

    fun start(scope: CoroutineScope) = scope.launch { loop() }

    val pending: List<Outgoing> get() = synchronized(items) { items.toList() }

    fun add(o: Outgoing) {
        synchronized(items) { items.add(o) }
        kick.trySend(Unit)
    }

    /** The connection is back (or something else changed): try now instead of waiting out the backoff. */
    fun wake() { kick.trySend(Unit) }

    fun retry(o: Outgoing) {
        if (o.state != Outgoing.State.FAILED) return
        o.state = Outgoing.State.QUEUED; o.note = null
        e.outgoingChanged(o)
        wake()
    }

    fun discard(o: Outgoing): Boolean {
        if (o.state == Outgoing.State.SENDING || o.state == Outgoing.State.SENT) return false
        synchronized(items) { items.remove(o) }
        e.outgoingGone(o)
        return true
    }

    /** The real message arrived from the server: its placeholder goes. */
    fun delivered(msgId: String) {
        val o = synchronized(items) { items.firstOrNull { it.msgId == msgId }?.also { items.remove(it) } } ?: return
        o.state = Outgoing.State.SENT
        e.outgoingGone(o)
    }

    private enum class Result { SENT, LATER, FAILED }

    private suspend fun loop() {
        var backoff = 1000L
        while (true) {
            val next = synchronized(items) { items.firstOrNull { it.state == Outgoing.State.QUEUED } }
            if (next == null) { kick.receive(); continue }
            when (attempt(next)) {
                Result.SENT -> {
                    backoff = 1000L
                    synchronized(items) { if (!next.visible) items.remove(next) }      // reactions and edits have no placeholder
                    if (!next.visible) e.outgoingGone(next)
                }
                Result.LATER -> {
                    next.state = Outgoing.State.QUEUED
                    next.note = "waiting for the connection"
                    e.outgoingChanged(next)
                    withTimeoutOrNull(backoff) { kick.receive() }
                    backoff = minOf(30_000L, backoff * 2)
                }
                Result.FAILED -> e.outgoingChanged(next)
            }
        }
    }

    private fun transient(x: ApiException) = x.offline || x.status >= 500 || x.status == 429 || x.status == 408

    private suspend fun attempt(o: Outgoing): Result {
        o.state = Outgoing.State.SENDING
        o.attempts++
        o.note = null
        e.outgoingChanged(o)
        val r = o.room
        return try {
            // attachments first, each uploaded once (a retry continues where the last one stopped)
            for (i in o.uploaded.size until o.files.size) {
                val f = o.files[i]
                o.note = "uploading ${i + 1}/${o.files.size}"
                e.outgoingChanged(o)
                val (ref, blobs) = e.uploadFile(r, f)
                o.uploaded.add(ref); o.blobs.addAll(blobs)
            }
            val payload = if (o.files.isEmpty()) o.base else JsonObject(o.base + ("files" to JsonArray(o.uploaded)))
            repeat(3) {
                val s = o.sealed ?: e.seal(r, payload).also { o.sealed = it; o.msgId = Canon.parseSigned(it.h, 4096).obj.str("id") }
                try {
                    e.api.call("rooms/" + r.id + "/send", buildJsonObject {
                        put("msg", buildJsonObject { put("h", s.h); put("c", s.c); put("s", s.s) })
                        put("blobs", buildJsonArray { o.blobs.forEach { add(JsonPrimitive(it)) } })
                        put("burn", payload.containsKey("burn"))
                    })
                    o.state = Outgoing.State.SENT
                    e.outgoingChanged(o)
                    return Result.SENT
                } catch (x: ApiException) {
                    when {
                        x.flag("duplicate") -> { o.state = Outgoing.State.SENT; e.outgoingChanged(o); return Result.SENT }
                        x.flag("rotate") || x.flag("stale") -> { e.refresh(); o.sealed = null; o.msgId = null }     // re-seal under the new key
                        else -> throw x
                    }
                }
            }
            Result.LATER                                                       // the room kept changing: try again shortly
        } catch (x: CancellationException) {
            throw x
        } catch (x: ApiException) {
            if (transient(x)) Result.LATER else fail(o, x.message)
        } catch (x: java.io.IOException) {
            Result.LATER
        } catch (x: Exception) {
            if (x !is CryptoFail && x !is IllegalStateException && x !is IllegalArgumentException) throw x
            fail(o, x.message)
        }
    }

    private fun fail(o: Outgoing, why: String?): Result {
        o.state = Outgoing.State.FAILED
        o.note = why ?: "the server refused it"
        return Result.FAILED
    }

    // ------------------------------------------------------------------------------------------- across a lock
    /**
     * Text messages still waiting, in a form safe to keep in the app's vault while the chat is locked: the payload and,
     * once sealed, the sealed message (so a resend after unlocking can't duplicate one that did arrive). Attachments
     * aren't kept (the files may be large); they're listed in [droppedOnLock].
     */
    fun snapshot(): List<JsonObject> = pending.filter { it.files.isEmpty() && it.state != Outgoing.State.SENT }.map { o ->
        buildJsonObject {
            put("room", o.room.id); put("kind", o.kind); put("preview", o.preview); put("payload", o.base)
            o.sealed?.let { s -> put("sealed", buildJsonObject { put("h", s.h); put("c", s.c); put("s", s.s) }) }
        }
    }

    val droppedOnLock: Int get() = pending.count { it.files.isNotEmpty() && it.state != Outgoing.State.SENT }

    fun restore(saved: List<JsonObject>) {
        for (j in saved) {
            val r = e.roomById(j.strOrNull("room") ?: continue) ?: continue
            val payload = j["payload"] as? JsonObject ?: continue
            val o = Outgoing(r, j.strOrNull("kind") ?: "text", j.strOrNull("preview") ?: "", payload, emptyList())
            (j["sealed"] as? JsonObject)?.let { s ->
                o.sealed = RoomCrypto.SealedMsg(s.str("h"), s.str("c"), s.str("s"))
                o.msgId = Canon.parseSigned(s.str("h"), 4096).obj.str("id")
            }
            e.outgoingAdded(o)
            add(o)
        }
    }
}

