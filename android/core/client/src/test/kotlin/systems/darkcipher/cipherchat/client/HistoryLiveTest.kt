package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import systems.darkcipher.cipherchat.crypto.arr
import systems.darkcipher.cipherchat.crypto.hex
import systems.darkcipher.cipherchat.crypto.long
import systems.darkcipher.cipherchat.crypto.random
import systems.darkcipher.cipherchat.crypto.str
import java.io.File
import java.net.URI
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Devices, the key store and history (PROTOCOL.md §10) against a REAL server, the same steps as the Windows engine's
 * HistoryLiveTests and the same switches as [LiveServerTest]: a first phone keeps the key it opens and the server
 * deletes its wrap; a second phone gets history after the first approves it (device codes match) and reads the older
 * message from its own store with no wrap left; removing the second phone wipes its store.
 */
class HistoryLiveTest {
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

    private suspend fun <T> paced(call: suspend () -> T): T =
        try { call() } catch (e: ApiException) { if (e.status != 429) throw e; delay(61_000); call() }

    private suspend fun until(what: String, seconds: Int = 30, cond: () -> Boolean) {
        repeat(seconds * 10) { if (cond()) return; delay(100) }
        throw AssertionError("timed out waiting for $what")
    }

    /** Signs each session out, so none is left looking like an older app that keeps no key store (which would put that
     *  person, often the owner, in compatibility mode for the next test). */
    private suspend fun signOut(apis: List<ChatApi>) {
        for (a in apis) if (a.hasSession) try { a.logout() } catch (e: Exception) { if (e is CancellationException) throw e }
    }

    private object Plain : StoreGuard {
        override fun protect(plain: ByteArray) = plain.copyOf()
        override fun unprotect(sealed: ByteArray) = sealed.copyOf()
    }

    @Test fun aPhoneKeepsKeysAndHandsHistoryToANewOne() = runBlocking {
        val origin = env("CIPHERCHAT_DEV_ORIGIN")
        assumeTrue("CIPHERCHAT_DEV_ORIGIN not set", origin != null)
        val uri = URI(origin!!)
        fun t(): Transport = if (uri.scheme == "https") PqTlsTransport(uri) else LoopbackDevTransport(uri)
        val ua = "CipherChat/0.1 (Android; host tests)"
        val dir = File("build/history-live-" + hex(random(4))).apply { mkdirs() }
        var apis = listOf<ChatApi>()
        try {
            // ---- the owner, and a fresh person with an identity, pinned and certified
            val ownerApi = ChatApi(t(), ua).also { apis = apis + it }
            paced { ownerApi.login(env("CIPHERCHAT_DEV_OWNER")!!, env("CIPHERCHAT_DEV_OWNER_PASSWORD")!!, totp(env("CIPHERCHAT_DEV_OWNER_TOTP")!!)) }
            val ownerMe = Gate.unlock(ownerApi, ownerApi.call("state"), env("CIPHERCHAT_DEV_OWNER_PASSPHRASE")!!.toCharArray())
            val user = "ahist" + hex(random(3))
            val inv = ownerApi.call("admin/users/invite", buildJsonObject { put("username", user); put("role", "member") })
            val token = inv["link"]!!.jsonObject.str("url").substringAfter("#enrol=")
            val api1 = ChatApi(t(), ua).also { apis = apis + it }
            val pw = "android history test password 1"
            val secret = paced { api1.call("auth/enrol/start", buildJsonObject { put("token", token); put("password", pw) }) }.str("secret")
            paced { api1.call("auth/enrol/finish", buildJsonObject { put("token", token); put("code", totp(secret, -1)) }) }
            paced { api1.login(user, pw, totp(secret)) }
            val pass = "android history test chat passphrase".toCharArray()
            val me1 = Gate.setup(api1, api1.call("state"), pass, reset = false, ask = { null })
            val owner = ChatEngine(ownerApi, ownerMe)
            owner.refresh()
            Gate.pinOwner(api1, api1.call("state"), me1, pass, { null })
            owner.certify(owner.people[user]!!)

            // ---- phone 1 joins the device list and keeps the key it opens; its wrap is deleted
            val p1 = ChatEngine(api1, me1)
            p1.useStore(me1.openStore(File(dir, "p1.bin"), Plain, "Phone one"))
            owner.start()
            p1.start()
            assertEquals(1, p1.keyDevices()!!.devices.size)
            val room = owner.createRoom("ahist-$user", "history test", 0, listOf(user))
            owner.openRoom(room)
            owner.sendText(room, "before the new phone")
            until("the owner's own message") { room.snapshot().any { it.message?.text == "before the new phone" } }
            p1.refresh()
            val r1 = p1.roomById(room.id)!!
            p1.openRoom(r1)
            until("the message on phone 1") { r1.snapshot().any { it.message?.text == "before the new phone" } }
            assertTrue(p1.store!!.has(room.id, 1))
            suspend fun wrapGone(api: ChatApi) = api.call("rooms/${room.id}/epochs?all=1").arr("items").filterIsInstance<JsonObject>()
                .all { (it["body"] as JsonObject)["w"] == null || (it["body"] as JsonObject)["w"].toString() == "null" }
            repeat(50) { if (!wrapGone(api1)) delay(100) }
            assertTrue("the wrap phone 1 acknowledged is deleted", wrapGone(api1))

            // ---- phone 2 signs in, joins, asks for history; phone 1 approves after the codes match
            val api2 = ChatApi(t(), ua).also { apis = apis + it }
            paced { api2.login(user, pw, totp(secret, 1)) }
            val me2 = Gate.unlock(api2, api2.call("state"), pass)
            val p2 = ChatEngine(api2, me2)
            p2.useStore(me2.openStore(File(dir, "p2.bin"), Plain, "Phone two"))
            var shown: String? = null
            p1.confirmSync = { _, _, code -> shown = code; true }
            p2.start()
            assertEquals(2, p2.keyDevices()!!.devices.size)
            until("the history package on phone 2", 60) { p2.store?.has(room.id, 1) == true }
            assertEquals(p2.store!!.code(), shown)
            val r2 = p2.roomById(room.id)!!
            p2.openRoom(r2)
            until("the older message on phone 2") { r2.snapshot().any { it.message?.text == "before the new phone" } }
            assertTrue("phone 2 read it from its own store, with no wrap on the server", wrapGone(api2))

            // ---- removing phone 2 on phone 1 wipes phone 2's store the next time it looks
            val list = p1.keyDevices()!!
            p1.removeKeyDevice(list, list.devices.single { it.id == p2.store!!.dev })
            p2.refresh()
            until("phone 2 to notice it was removed") { p2.store == null }
            assertFalse(File(dir, "p2.bin").exists())
            assertTrue(File(dir, "p1.bin").exists())
            owner.lock(); p1.lock(); p2.lock()
        } finally { signOut(apis); dir.deleteRecursively() }
    }

    /**
     * Protocol 2 (PROTOCOL.md §11), the same steps as the Windows engine's test: with the owner and a person on two
     * phones, all keeping key stores and prekeys, a new room key is sealed to each of the three devices' prekeys; each
     * device gets only its own wrap (none without ?dev=), reads the message, and the wraps go once acknowledged.
     */
    @Test fun newRoomKeysAreSealedToEachDevicesPrekey() = runBlocking {
        val origin = env("CIPHERCHAT_DEV_ORIGIN")
        assumeTrue("CIPHERCHAT_DEV_ORIGIN not set", origin != null)
        val uri = URI(origin!!)
        fun t(): Transport = if (uri.scheme == "https") PqTlsTransport(uri) else LoopbackDevTransport(uri)
        val ua = "CipherChat/0.1 (Android; host tests)"
        val dir = File("build/prekey-live-" + hex(random(4))).apply { mkdirs() }
        var apis = listOf<ChatApi>()
        try {
            val ownerApi = ChatApi(t(), ua).also { apis = apis + it }
            paced { ownerApi.login(env("CIPHERCHAT_DEV_OWNER")!!, env("CIPHERCHAT_DEV_OWNER_PASSWORD")!!, totp(env("CIPHERCHAT_DEV_OWNER_TOTP")!!)) }
            val ownerMe = Gate.unlock(ownerApi, ownerApi.call("state"), env("CIPHERCHAT_DEV_OWNER_PASSPHRASE")!!.toCharArray())
            val user = "apk" + hex(random(3))
            val inv = ownerApi.call("admin/users/invite", buildJsonObject { put("username", user); put("role", "member") })
            val token = inv["link"]!!.jsonObject.str("url").substringAfter("#enrol=")
            val api1 = ChatApi(t(), ua).also { apis = apis + it }
            val pw = "android prekey test password 1"
            val secret = paced { api1.call("auth/enrol/start", buildJsonObject { put("token", token); put("password", pw) }) }.str("secret")
            paced { api1.call("auth/enrol/finish", buildJsonObject { put("token", token); put("code", totp(secret, -1)) }) }
            paced { api1.login(user, pw, totp(secret)) }
            val pass = "android prekey test chat passphrase".toCharArray()
            val me1 = Gate.setup(api1, api1.call("state"), pass, reset = false, ask = { null })
            val owner = ChatEngine(ownerApi, ownerMe)
            owner.useStore(ownerMe.openStore(File(dir, "owner.bin"), Plain, "Owner phone"))
            owner.refresh()
            Gate.pinOwner(api1, api1.call("state"), me1, pass, { null })
            owner.certify(owner.people[user]!!)
            owner.start()
            // (this test server's owner may have devices from earlier runs, with no fresh prekeys: only this one stays)
            while (true) {
                val list = owner.keyDevices()!!
                if (list.devices.size <= 1) break
                owner.removeKeyDevice(list, list.devices.first { it.id != owner.store!!.dev })
            }

            val p1 = ChatEngine(api1, me1)
            p1.useStore(me1.openStore(File(dir, "p1.bin"), Plain, "Phone one"))
            p1.confirmSync = { _, _, _ -> false }
            p1.start()
            val api2 = ChatApi(t(), ua).also { apis = apis + it }
            paced { api2.login(user, pw, totp(secret, 1)) }
            val me2 = Gate.unlock(api2, api2.call("state"), pass)
            val p2 = ChatEngine(api2, me2)
            p2.useStore(me2.openStore(File(dir, "p2.bin"), Plain, "Phone two"))
            p2.start()
            // straight away, as an app would: each device published its prekey while unlocking, and the owner's
            // cached directory (older than phone 2's prekey) is looked at again before settling for compatibility mode
            val room = owner.createRoom("av2-$user", "prekey test", 0, listOf(user))
            owner.openRoom(room)
            owner.sendText(room, "sealed to each device")
            until("the owner's own message") { room.snapshot().any { it.message?.text == "sealed to each device" } }
            assertTrue(room.snapshot().any { it.text.contains("sealed to each of their 3 devices") })
            assertEquals(2L, room.headers[1]!!.long("v"))

            // each phone gets its own wrap, and none without saying which device it is
            suspend fun wrap(api: ChatApi, q: String) = api.call("rooms/${room.id}/epochs?all=1$q").arr("items").filterIsInstance<JsonObject>()
                .single { it.long("epoch") == 1L }.let { (it["body"] as JsonObject)["w"]?.takeIf { w -> w.toString() != "null" }?.toString() }
            assertNull(wrap(api1, ""))
            p1.refresh(); p2.refresh()
            for ((p, name) in listOf(p1 to "phone 1", p2 to "phone 2")) {
                val r = p.roomById(room.id)!!
                p.openRoom(r)
                until("the message on $name") { r.snapshot().any { it.message?.text == "sealed to each device" } }
                assertTrue(p.store!!.has(room.id, 1))
            }
            repeat(50) { if (wrap(api1, "&dev=" + p1.store!!.dev) != null || wrap(api2, "&dev=" + p2.store!!.dev) != null) delay(100) }
            assertNull(wrap(api1, "&dev=" + p1.store!!.dev))
            assertNull(wrap(api2, "&dev=" + p2.store!!.dev))

            // phone 3 joins after key #1 (nobody hands it older keys) and, as a plain member, renews the key straight
            // away: the new key still follows on from #1, whose header phone 3 checked but can't open
            p2.confirmSync = { _, _, _ -> false }
            val used = System.currentTimeMillis() / 30_000 + 1                  // phone 2's code was for the next window at most
            while (System.currentTimeMillis() / 30_000 < used) delay(1000)
            val api3 = ChatApi(t(), ua).also { apis = apis + it }
            paced { api3.login(user, pw, totp(secret, 1)) }
            val me3 = Gate.unlock(api3, api3.call("state"), pass)
            val p3 = ChatEngine(api3, me3)
            p3.useStore(me3.openStore(File(dir, "p3.bin"), Plain, "Phone three"))
            p3.start()
            val r3 = p3.roomById(room.id)!!
            p3.openRoom(r3)
            val before = r3.epoch
            assertFalse("phone 3 doesn't hold the current key", p3.store!!.has(room.id, before))
            p3.rotateNow(r3)
            val next = before + 1
            until("the owner opening phone 3's key") { room.headers.containsKey(next) }
            assertEquals(room.hashes[before], room.headers[next]!!.str("prev"))
            assertFalse(room.snapshot().any { it.text.contains("doesn't follow on") })
            val line = room.snapshot().last { it.text.startsWith("new room key #$next ") }.text
            val names = line.substringAfter(" for ").substringBefore(" (").split(", ")
            assertEquals(names.size, names.distinct().size)                     // one name per person, not one per device
            assertTrue(user in names)
            p3.lock()
            owner.lock(); p1.lock(); p2.lock()
        } finally { signOut(apis); dir.deleteRecursively() }
    }
}
