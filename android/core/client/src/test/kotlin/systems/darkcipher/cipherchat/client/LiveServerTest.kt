package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.random
import systems.darkcipher.cipherchat.crypto.str
import java.net.URI
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Two people chatting (and setting up a call) through a real CipherChat server, with the phone's engine on both ends:
 * the same steps as the Windows engine's live test. Runs only when CIPHERCHAT_DEV_ORIGIN, CIPHERCHAT_DEV_OWNER,
 * CIPHERCHAT_DEV_OWNER_PASSWORD, CIPHERCHAT_DEV_OWNER_TOTP and CIPHERCHAT_DEV_OWNER_PASSPHRASE are set (a throwaway
 * demo owner whose identity already exists).
 */
/** A network that can go away (every request fails) or lose the answer to the next message send after the server got it. */
class FlakyTransport(private val inner: Transport) : Transport {
    @Volatile var down = false
    @Volatile var loseNextSendAnswer = false
    @Volatile var lostAnswers = 0
    override val origin get() = inner.origin
    override suspend fun send(request: HttpRequest): HttpResult {
        if (down) throw java.io.IOException("network down")
        val res = inner.send(request)
        if (loseNextSendAnswer && request.pathAndQuery.endsWith("/send")) {
            loseNextSendAnswer = false
            lostAnswers++
            throw java.io.IOException("connection dropped before the answer")
        }
        return res
    }
}

class LiveServerTest {
    private fun env(k: String): String? = System.getenv(k)?.takeIf { it.isNotEmpty() }

    private fun totp(secret: String, offset: Int = 0): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var bits = 0; var v = 0
        val key = ArrayList<Byte>()
        for (c in secret.trimEnd('=')) { v = (v shl 5) or alphabet.indexOf(c); bits += 5; if (bits >= 8) { key.add((v shr (bits - 8)).toByte()); bits -= 8 } }
        val step = System.currentTimeMillis() / 1000 / 30 + offset
        val msg = ByteArray(8) { (step shr (56 - 8 * it)).toByte() }
        val h = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key.toByteArray(), "HmacSHA1")) }.doFinal(msg)
        val o = h.last().toInt() and 15
        val n = ((h[o].toInt() and 0x7f) shl 24 or ((h[o + 1].toInt() and 0xff) shl 16) or ((h[o + 2].toInt() and 0xff) shl 8) or (h[o + 3].toInt() and 0xff)) % 1_000_000
        return n.toString().padStart(6, '0')
    }

    // The server allows 6 sign-in attempts a minute per connection, and every test request comes through one; wait it out
    private suspend fun <T> paced(call: suspend () -> T): T =
        try { call() } catch (e: ApiException) { if (e.status != 429) throw e; delay(61_000); call() }

    private suspend fun until(what: String, seconds: Int = 30, cond: () -> Boolean) {
        repeat(seconds * 10) { if (cond()) return; delay(100) }
        throw AssertionError("timed out waiting for $what")
    }

    @Test fun twoPeopleChatAndCallThroughTheRealServer() = runBlocking {
        val origin = env("CIPHERCHAT_DEV_ORIGIN")   // the server checks Origin exactly: use the name it was set up with (e.g. http://localhost:8094)
        assumeTrue("CIPHERCHAT_DEV_ORIGIN not set", origin != null)
        val ownerUser = env("CIPHERCHAT_DEV_OWNER")!!
        val uri = URI(origin!!)
        fun t(): Transport = if (uri.scheme == "https") PqTlsTransport(uri) else LoopbackDevTransport(uri)
        val ua = "CipherChat/0.1 (Android; host tests)"

        // ---- the owner signs in and unlocks
        val ownerApi = ChatApi(t(), ua)
        paced { ownerApi.login(ownerUser, env("CIPHERCHAT_DEV_OWNER_PASSWORD")!!, totp(env("CIPHERCHAT_DEV_OWNER_TOTP")!!)) }
        val st = ownerApi.call("state")
        assertThrows(WrongPassphrase::class.java) { runBlocking { Gate.unlock(ownerApi, st, "not the passphrase at all, sorry".toCharArray()) } }
        val ownerMe = Gate.unlock(ownerApi, st, env("CIPHERCHAT_DEV_OWNER_PASSPHRASE")!!.toCharArray())
        assertNotNull(ownerMe.anchorFp)

        // ---- a new person: invited, enrolled, signed in, identity created
        val user = "and" + systems.darkcipher.cipherchat.crypto.hex(random(3))
        val inv = ownerApi.call("admin/users/invite", buildJsonObject { put("username", user); put("role", "member") })
        val token = inv["link"]!!.jsonObject.str("url").substringAfter("#enrol=")
        val flaky = FlakyTransport(t())
        val userApi = ChatApi(flaky, ua)
        val pw = "android engine test password 1"
        val secret = paced { userApi.call("auth/enrol/start", buildJsonObject { put("token", token); put("password", pw) }) }.str("secret")
        paced { userApi.call("auth/enrol/finish", buildJsonObject { put("token", token); put("code", totp(secret, -1)) }) }
        paced { userApi.login(user, pw, totp(secret)) }
        var ust = userApi.call("state")
        val pass = "android engine test chat passphrase".toCharArray()
        assertThrows(IllegalArgumentException::class.java) { runBlocking { Gate.setup(userApi, ust, "too short".toCharArray(), false, null) } }
        val userMe = Gate.setup(userApi, ust, pass, reset = false, ask = { null })
        assertNull(userMe.anchorFp)

        // ---- the same safety number on both sides, then the user pins and the owner certifies
        val owner = ChatEngine(ownerApi, ownerMe)
        owner.refresh()
        val them = owner.people[user]!!
        assertEquals(TrustLevel.PENDING, them.trust)
        ust = userApi.call("state")
        assertEquals(owner.safetyNumber(them), Gate.ownerSafetyNumber(ust, userMe))
        Gate.pinOwner(userApi, ust, userMe, pass, { null })
        owner.certify(them)
        assertEquals(TrustLevel.OK, owner.people[user]!!.trust)

        val alice = ChatEngine(userApi, userMe)
        owner.start()
        alice.start()
        assertEquals(TrustLevel.OK, alice.people[ownerUser]!!.trust)

        // ---- a room, text, a file, a reaction, an edit
        val room = owner.createRoom("and-$user", "engine test", 1, listOf(user))
        owner.openRoom(room)
        owner.sendText(room, "hello from the Android engine ✓")
        val pic = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) + random(90_000)
        owner.sendFiles(room, "a picture", listOf(ChatEngine.OutgoingFile("test.png", pic)))
        alice.refresh()
        val aroom = alice.roomById(room.id)!!
        alice.openRoom(aroom)
        until("both messages at alice") { aroom.snapshot().count { it.message != null } >= 2 }
        val msgs = aroom.snapshot().mapNotNull { it.message }
        assertEquals("hello from the Android engine ✓", msgs[0].text)
        assertEquals("image", msgs[1].files[0].kind)
        assertArrayEquals(pic, alice.fetchFile(aroom, msgs[1].files[0]))

        val changed = AtomicInteger()
        owner.addListener(object : ChatListener { override fun entryChanged(room: Room, entry: Entry) { changed.incrementAndGet() } })
        alice.react(aroom, msgs[0], "👍", true)
        fun ownerHello() = owner.roomById(room.id)!!.snapshot().firstOrNull { it.message?.text?.startsWith("hello") == true }?.message
        until("the reaction at the owner") { ownerHello()?.reactions?.isNotEmpty() == true }
        assertTrue(user in ownerHello()!!.reactions[0].second)
        assertTrue(changed.get() > 0)
        owner.edit(room, ownerHello()!!, "hello, edited")
        until("the edit at alice") { msgs[0].text == "hello, edited" }

        // ---- a burn message: hidden until revealed, destroyed on the server once read
        owner.sendText(room, "this burns", burn = 10)
        until("the burn message at alice") { aroom.snapshot().any { it.message?.burn == 10 } }
        val burn = aroom.snapshot().first { it.message?.burn == 10 }.message!!
        alice.revealBurn(aroom, burn)
        alice.burnOut(aroom, burn)
        until("the burn message to be destroyed for the owner") { owner.roomById(room.id)!!.snapshot().none { it.message?.burn == 10 } }

        // ---- bad network: alice's link drops; her messages wait, then arrive once each and in order
        flaky.down = true
        alice.sendText(aroom, "queued while offline 1")
        alice.sendText(aroom, "queued while offline 2")
        delay(2500)
        assertTrue(alice.outgoing.size == 2 && alice.outgoing.all { it.state == Outgoing.State.QUEUED })
        assertTrue(aroom.snapshot().count { it.outgoing != null } == 2)                // shown as waiting placeholders
        flaky.down = false
        alice.networkChanged()
        fun ownerTexts() = owner.roomById(room.id)!!.snapshot().mapNotNull { it.message?.text }
        until("both queued messages at the owner", 60) { ownerTexts().containsAll(listOf("queued while offline 1", "queued while offline 2")) }
        assertTrue(ownerTexts().indexOf("queued while offline 1") < ownerTexts().indexOf("queued while offline 2"))
        until("the placeholders to go") { aroom.snapshot().none { it.outgoing != null } }
        // the server stores a message but its answer never arrives: the resend is recognised, not duplicated
        flaky.loseNextSendAnswer = true
        alice.sendText(aroom, "answer lost once")
        until("the lost-answer message at the owner", 60) { "answer lost once" in ownerTexts() }
        until("alice's outbox to empty", 60) { alice.outgoing.isEmpty() }
        delay(1500)
        assertEquals(1, ownerTexts().count { it == "answer lost once" })
        assertTrue(flaky.lostAnswers == 1)

        // ---- a call: alice's ring reaches the owner verified, call words agree, a sender key unwraps
        val rings = ArrayList<IncomingCall>()
        owner.calls.addListener(object : CallListener { override fun ringing(call: IncomingCall) { synchronized(rings) { rings.add(call) } } })
        val callId = systems.darkcipher.cipherchat.crypto.Call.newCallId()
        val to = buildJsonArray { add(JsonPrimitive(ownerUser)) }
        val ring = alice.calls.seal(buildJsonObject {
            put("kind", "ring"); put("room", room.id); put("call", callId); put("dev", alice.calls.device); put("to", to)
            put("media", "video"); put("people", buildJsonArray { add(JsonPrimitive(user)); add(JsonPrimitive(ownerUser)) })
        })
        alice.calls.signal(buildJsonObject { put("room", room.id); put("to", to); put("sig", ring) })
        until("the ring at the owner") { synchronized(rings) { rings.isNotEmpty() } }
        assertEquals(IncomingCall(callId, room.id, user, "video", listOf(user, ownerUser)), rings[0])
        assertEquals(owner.calls.words(callId, listOf(user, ownerUser)), alice.calls.words(callId, listOf(ownerUser, user)))
        val kept = owner.calls.open(callId)
        assertTrue(kept.isNotEmpty())
        assertThrows(CryptoFail::class.java) { owner.calls.seal(buildJsonObject { put("dev", "someone-else") }) }
        val senderKey = random(32)
        val keyFields = alice.calls.wrapKey(senderKey, callId, 1, listOf(ownerUser))
        val keySig = alice.calls.seal(JsonObject(keyFields + buildJsonObject {
            put("kind", "key"); put("room", room.id); put("call", callId); put("dev", alice.calls.device); put("to", to)
        }))
        val got = ArrayList<JsonObject>()
        owner.calls.addListener(object : CallListener { override fun signals(items: kotlinx.serialization.json.JsonArray) { synchronized(got) { items.forEach { got.add(it.jsonObject) } } } })
        alice.calls.signal(buildJsonObject { put("room", room.id); put("to", to); put("sig", keySig) })
        until("the key signal on the owner's call screen") { synchronized(got) { got.any { it["kind"]?.toString() == "\"key\"" } } }
        val opened = owner.calls.openSignal(got.first { it["kind"]?.toString() == "\"key\"" })
        assertArrayEquals(senderKey, owner.calls.unwrapKey(opened))
        assertThrows(CryptoFail::class.java) { owner.calls.openSignal(got.first { it["kind"]?.toString() == "\"key\"" }) }   // replay
        assertTrue(owner.calls.turn().isNotEmpty())
        owner.calls.closed()

        owner.lock()
        alice.lock()
        ownerApi.call("admin/users/$user/delete", JsonObject(emptyMap()))     // tidy up the demo server
        Unit
    }
}
