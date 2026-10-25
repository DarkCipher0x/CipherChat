package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The phone's attachments, payload checks and call crypto, against what the browser and Windows make (the same
 * fixtures their own tests use): the phone must open them, and refuse anything changed.
 */
class CallAndFileTest {
    private fun fixture(name: String): JsonObject =
        Json.parseToJsonElement(javaClass.getResource("/interop/$name")!!.readText()).jsonObject

    private fun pattern(n: Int) = ByteArray(n) { ((it * 7 + 3) and 255).toByte() }

    @Test fun opensFilesTheBrowserAndWindowsSealed() {
        for (name in listOf("browser-files.json", "windows-files.json")) {
            val files = fixture(name).arr("files")
            assertEquals(5, files.size)
            for (f in files) {
                val x = f.jsonObject
                val plain = Files.open(unb64(x.str("sealed")), x.str("key"), x.long("size"), x.str("sha3"))
                assertEquals(x.str("plain_sha3"), hex(sha3_256(plain)))
                assertArrayEquals(pattern(x.long("size").toInt()), plain)
            }
        }
    }

    @Test fun refusesChangedAttachments() {
        val s = Files.seal(pattern(200_000))
        assertArrayEquals(pattern(200_000), Files.open(s.data, s.key, s.size, s.sha3))
        val flipped = s.data.copyOf().also { it[70_000] = (it[70_000].toInt() xor 1).toByte() }
        assertThrows(CryptoFail::class.java) { Files.open(flipped, s.key, s.size, hex(sha3_256(flipped))) }   // even with a matching hash
        assertThrows(CryptoFail::class.java) { Files.open(s.data, s.key, 1, s.sha3) }                         // a size that implies an extra chunk
        assertThrows(CryptoFail::class.java) { Files.open(s.data, b64(random(32)), s.size, s.sha3) }          // the wrong key
        assertEquals("image/png", Files.sniff(byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0, 0)))
        assertEquals("application/octet-stream", Files.sniff("<svg".toByteArray()))
    }

    @Test fun payloadsAreCheckedLikeTheOthers() {
        fun p(json: String) = Json.parseToJsonElement(json).jsonObject
        Payload.check(p("""{"k":"text","text":"hi"}"""))
        Payload.check(p("""{"text":"hi","burn":30}"""))
        Payload.check(p("""{"k":"react","text":"","target":"AAAAAAAAAAAAAAAAAAAAAA","emoji":"👍","on":true}"""))
        for (bad in listOf("""{"k":"react","text":"","target":"short","emoji":"x","on":true}""", """{"k":"text","text":"x","burn":5}""",
                           """{"k":"edit","text":"x","target":"AAAAAAAAAAAAAAAAAAAAAA","burn":30}""", """{"k":"bogus","text":"x"}""",
                           """{"k":"file","text":"","files":[]}"""))
            assertThrows(CryptoFail::class.java) { Payload.check(p(bad)) }
    }

    @Test fun callWordsMatchTheBrowserAndWindows() {
        assertEquals("coyote meadow willow pebble", Call.callWords("A".repeat(22), listOf("bob" to "b".repeat(64), "alice" to "a".repeat(64))).joinToString(" "))
        assertEquals("oyster autumn amber hazel", Call.callWords("Zq0-_x".padEnd(22, '9'), listOf("owner.demo" to "0123456789abcdef".repeat(4))).joinToString(" "))
    }

    @Test fun opensACallSignalWindowsMade() {
        val f = fixture("windows-call.json")
        val a = f["alice"]!!.jsonObject
        val alice = openIdentity(a.str("b"), a.str("s"), "alice")
        val bob = identityFromMaster("bob", fromHex(f.str("bob_master")))
        val bobFp = publishIdentity(bob, 1_790_000_000_000).fp
        val item = f["item"]!!.jsonObject
        val at = f.long("made_at")
        val sig = Call.open(item, { if (it == "alice") alice else null }, mutableSetOf(), now = at)
        assertEquals("key", sig.str("kind"))
        assertEquals(f.str("key"), hex(Call.unwrapSenderKey(sig, bob, bobFp)))
        assertThrows(CryptoFail::class.java) { Call.open(item, { null }, mutableSetOf(), now = at) }               // untrusted sender
        assertThrows(CryptoFail::class.java) { Call.open(item, { alice }, mutableSetOf(), now = at + 600_000) }     // stale
    }

    @Test fun signalsAndSenderKeysRoundTrip() {
        val alice = identityFromMaster("alice", random(32))
        val aPub = publishIdentity(alice, 1).let { openIdentity(it.b, it.s, "alice") }
        val bob = identityFromMaster("bob", random(32))
        val bPub = publishIdentity(bob, 1).let { openIdentity(it.b, it.s, "bob") }
        val call = Call.newCallId()
        val dev = Call.newDeviceId()
        val key = random(32)
        val fields = JsonObject(Call.wrapSenderKey(key, call, alice, dev, 2, listOf(bPub)) + buildJsonObject {
            put("kind", "key"); put("room", "r".repeat(16)); put("call", call); put("dev", dev); put("to", JsonArray(listOf(JsonPrimitive("bob"))))
        })
        val sig = Call.seal(alice, aPub.fp, fields)
        val item = buildJsonObject { put("room", "r".repeat(16)); put("from", "alice"); put("kind", "key"); put("call", call); put("sig", sig) }
        val seen = mutableSetOf<String>()
        val opened = Call.open(item, { if (it == "alice") aPub else null }, seen)
        assertArrayEquals(key, Call.unwrapSenderKey(opened, bob, bPub.fp))
        assertThrows(CryptoFail::class.java) { Call.open(item, { aPub }, seen) }                                     // replay
        assertTrue(opened["to"]!!.jsonArray.size == 1)
    }
}
