package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The protocol on its own (same cases as the web chat's selftest.html). Browser interop is in InteropTest. */
class CryptoTest {
    private fun refuses(what: String, block: () -> Unit) {
        try { block(); fail("$what was accepted") } catch (e: CryptoFail) { /* refused, as it must be */ }
    }

    @Test fun selfTestPasses() {
        val checks = SelfTest.run()
        assertTrue(checks.size >= 12)
        assertTrue(checks.all { it.ok })
    }

    @Test fun canonicalJsonMatchesJavaScript() {
        val o = buildJsonObject { put("b", "x\"y\\\n\u0001é😀"); put("a", 12); put("c", true) }
        assertEquals("{\"a\":12,\"b\":\"x\\\"y\\\\\\n\\u0001é😀\",\"c\":true}", Canon.encode(o))
        refuses("a non-integer") { Canon.encode(buildJsonObject { put("x", 1.5) }) }
        refuses("a non-canonical header") { Canon.parseSigned(b64(utf8("{\"v\":1, \"a\":2}")), 100) }
        refuses("a header with keys out of order") { Canon.parseSigned(b64(utf8("{\"v\":1,\"a\":2}")), 100) }
        assertEquals(1L, Canon.parseSigned(b64(utf8("{\"a\":2,\"v\":1}")), 100).obj.long("v"))
    }

    @Test fun identitiesAreDeterministicAndSelfSigned() {
        val master = random(32)
        val a1 = publishIdentity(identityFromMaster("carol", master), 7)
        val a2 = publishIdentity(identityFromMaster("carol", master), 7)
        assertEquals(a1.fp, a2.fp)                                   // new device -> same identity
        assertNotEquals(a1.s, a2.s)                                  // hedged signatures
        val pub = openIdentity(a1.b, a1.s, "carol", a1.fp)
        assertEquals(1568, pub.kemPq.size)
        refuses("an identity claimed for someone else") { openIdentity(a1.b, a1.s, "bob") }
        val other = publishIdentity(identityFromMaster("carol", random(32)), 7)
        refuses("an identity with someone else's signature") { openIdentity(a1.b, other.s, "carol") }
        refuses("a wrong expected fingerprint") { openIdentity(a1.b, a1.s, "carol", other.fp) }
    }

    @Test fun certificatesAndSafetyNumbers() {
        val owner = identityFromMaster("dcx-admin", random(32)); val o = publishIdentity(owner, 1)
        val alice = identityFromMaster("alice", random(32)); val a = publishIdentity(alice, 1)
        val ownerPub = openIdentity(o.b, o.s, "dcx-admin")
        val cert = makeCert(owner, o.fp, "alice", a.fp, 5)
        assertTrue(verifyCert(cert, ownerPub, "alice", a.fp))
        assertFalse(verifyCert(cert, ownerPub, "alice", o.fp))
        assertFalse(verifyCert(makeCert(alice, a.fp, "alice", a.fp, 5), ownerPub, "alice", a.fp))
        val sn = safetyNumber(o.fp, a.fp)
        assertEquals(sn, safetyNumber(a.fp, o.fp))
        assertTrue(Regex("^(\\d{5} ){11}\\d{5}$").matches(sn))
    }

    @Test fun backupSealsAndRefusesTheWrongInputs() {
        val pepper = random(32)
        val payload = buildJsonObject { put("v", 1); put("master", b64(random(32))); put("anchor_fp", "ab".repeat(32)) }
        val sealed = Backup.seal("alice", "correct horse battery staple 42".toCharArray(), pepper, 1, payload)
        assertEquals(payload, Backup.open("alice", "correct horse battery staple 42".toCharArray(), pepper, sealed))
        refuses("a wrong passphrase") { Backup.open("alice", "correct horse battery staple 43".toCharArray(), pepper, sealed) }
        refuses("a wrong server key share") { Backup.open("alice", "correct horse battery staple 42".toCharArray(), random(32), sealed) }
        refuses("another account") { Backup.open("mallory", "correct horse battery staple 42".toCharArray(), pepper, sealed) }
        val weak = JsonObject(sealed + ("kdf" to JsonObject((sealed["kdf"] as JsonObject) + ("m" to JsonPrimitive(1024)))))
        refuses("weakened settings") { Backup.open("alice", "x".toCharArray(), pepper, weak) }
    }

    @Test fun roomKeysAndMessages() {
        val owner = identityFromMaster("dcx-admin", random(32)); val o = publishIdentity(owner, 1)
        val alice = identityFromMaster("alice", random(32)); val a = publishIdentity(alice, 1)
        val oPub = openIdentity(o.b, o.s, "dcx-admin"); val aPub = openIdentity(a.b, a.s, "alice")
        val room = "0123456789abcdef"
        val built = Room.buildEpoch(owner, o.fp, room, 1, listOf(Room.Recipient("alice", a.fp, aPub), Room.Recipient("dcx-admin", o.fp, oPub)), "")
        val got = Room.openEpoch(alice, a.fp, room, 1, "dcx-admin", built.pkg.h, built.pkg.s, built.pkg.w["alice"], oPub)
        assertTrue(sameBytes(built.key, got.key))
        refuses("someone else's copy") { Room.openEpoch(alice, a.fp, room, 1, "dcx-admin", built.pkg.h, built.pkg.s, built.pkg.w["dcx-admin"], oPub) }
        refuses("a key signed by another identity") { Room.openEpoch(alice, a.fp, room, 1, "dcx-admin", built.pkg.h, built.pkg.s, built.pkg.w["alice"], aPub) }
        refuses("a key replayed into another room") { Room.openEpoch(alice, a.fp, "fedcba9876543210", 1, "dcx-admin", built.pkg.h, built.pkg.s, built.pkg.w["alice"], oPub) }
        for (at in intArrayOf(5, 1580, 1640)) {
            val w = unb64(built.pkg.w.getValue("alice")).also { it[at] = (it[at].toInt() xor 1).toByte() }
            refuses("a changed wrapped key at $at") { Room.openEpoch(alice, a.fp, room, 1, "dcx-admin", built.pkg.h, built.pkg.s, b64(w), oPub) }
        }
        val m = Room.sealMessage(alice, a.fp, room, 1, got.key, Room.text("hello from the phone ✓"))
        val opened = Room.openMessage(room, 1, "alice", m.h, m.c, m.s, built.key, aPub)
        assertEquals("hello from the phone ✓", opened.text)
        assertEquals(12 + 256 + 16, unb64(m.c).size)
        val c = unb64(m.c).also { it[20] = (it[20].toInt() xor 1).toByte() }
        refuses("a changed ciphertext") { Room.openMessage(room, 1, "alice", m.h, b64(c), m.s, built.key, aPub) }
        refuses("another sender") { Room.openMessage(room, 1, "dcx-admin", m.h, m.c, m.s, built.key, oPub) }
        refuses("the wrong room key") { Room.openMessage(room, 1, "alice", m.h, m.c, m.s, random(32), aPub) }
        refuses("another epoch") { Room.openMessage(room, 2, "alice", m.h, m.c, m.s, built.key, aPub) }
    }
}
