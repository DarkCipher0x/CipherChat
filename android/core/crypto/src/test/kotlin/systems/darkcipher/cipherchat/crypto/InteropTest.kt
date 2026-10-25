package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Byte compatibility with the web chat, both directions.
 *   browser-made.json  made by the real crypto.js in a browser (fixed inputs, real signatures/ciphertexts): this test
 *                      must re-derive the same identities and open everything in it.
 *   phone-made.json    written by [phoneMakesAFixtureForTheBrowser]; the browser check (docs/INTEROP.md) opens it.
 */
class InteropTest {
    private val dir = File("src/test/resources/interop")
    private fun load(name: String) = Json.parseToJsonElement(File(dir, name).readText()).jsonObject
    private fun JsonObject.o(k: String) = getValue(k).jsonObject

    @Test fun phoneOpensWhatTheBrowserMade() = opens("browser-made.json")

    /** windows-made.json comes from the Windows app's InteropTests (BouncyCastle .NET); copied here unchanged. */
    @Test fun phoneOpensWhatWindowsMade() = opens("windows-made.json")

    private fun opens(fixture: String) {
        val f = load(fixture)
        val at = f.long("at")
        // Same master secret -> byte-identical public identity (ML-KEM, ML-DSA, X25519, Ed25519 and the SHA-3 seed derivation)
        val owner = identityFromMaster("dcx-admin", unb64(f.str("owner_master"), 32))
        val alice = identityFromMaster("alice", unb64(f.str("alice_master"), 32))
        assertEquals(f.o("owner").str("fp"), publishIdentity(owner, at).fp)
        assertEquals(f.o("alice").str("fp"), publishIdentity(alice, at).fp)
        assertEquals(f.o("owner").str("b"), publishIdentity(owner, at).b)
        // The browser's hybrid signatures verify here
        val oPub = openIdentity(f.o("owner").str("b"), f.o("owner").str("s"), "dcx-admin", f.o("owner").str("fp"))
        val aPub = openIdentity(f.o("alice").str("b"), f.o("alice").str("s"), "alice", f.o("alice").str("fp"))
        assertTrue(verifyCert(Signed64(f.o("cert").str("b"), f.o("cert").str("s")), oPub, "alice", aPub.fp))
        assertEquals(f.str("safety"), safetyNumber(oPub.fp, aPub.fp))
        // Argon2id + server key share + HKDF + AES-GCM: the browser's sealed backup opens with the same passphrase
        val bk = f.o("backup")
        val payload = Backup.open("alice", bk.str("passphrase").toCharArray(), unb64(bk.str("pepper"), 32), bk.o("sealed"))
        assertEquals(bk.o("payload"), payload)
        // The browser's room key (ML-KEM-1024 encapsulation + X25519 + combiner) unwraps for alice
        val e = f.o("epoch")
        val ep = Room.openEpoch(alice, aPub.fp, e.str("room"), e.long("epoch"), e.str("from"), e.str("h"), e.str("s"), e.str("w_alice"), oPub)
        assertEquals(e.str("key_sha3"), hex(sha3_256(ep.key)))
        // ...and the browser's message under it opens and verifies
        val m = f.o("message")
        val opened = Room.openMessage(m.str("room"), m.long("epoch"), m.str("from"), m.str("h"), m.str("c"), m.str("s"), ep.key, oPub)
        assertEquals(m.str("text"), opened.text)
    }

    @Test fun phoneMakesAFixtureForTheBrowser() {
        val at = 1792800000000L
        val ownerMaster = random(32); val aliceMaster = random(32)
        val owner = identityFromMaster("dcx-admin", ownerMaster); val alice = identityFromMaster("alice", aliceMaster)
        val o = publishIdentity(owner, at); val a = publishIdentity(alice, at)
        val oPub = openIdentity(o.b, o.s, "dcx-admin"); val aPub = openIdentity(a.b, a.s, "alice")
        val cert = makeCert(owner, o.fp, "alice", a.fp, at + 1)
        val pepper = random(32); val passphrase = "interop passphrase éè 2026"
        val payload = buildJsonObject { put("v", 1); put("master", b64(aliceMaster)); put("anchor_fp", o.fp); put("created", at) }
        val sealed = Backup.seal("alice", passphrase.toCharArray(), pepper, 1, payload)
        val room = "0123456789abcdef"
        val ep = Room.buildEpoch(owner, o.fp, room, 1, listOf(Room.Recipient("alice", a.fp, aPub), Room.Recipient("dcx-admin", o.fp, oPub)), "")
        val text = "from the phone: ```code``` ✓ 😀 <b>x</b>"
        val msg = Room.sealMessage(owner, o.fp, room, 1, ep.key, Room.text(text))
        val fixture = buildJsonObject {
            put("made_by", "CipherChat core:crypto (BouncyCastle)"); put("at", at)
            put("owner_master", b64(ownerMaster)); put("alice_master", b64(aliceMaster))
            put("owner", buildJsonObject { put("b", o.b); put("s", o.s); put("fp", o.fp) })
            put("alice", buildJsonObject { put("b", a.b); put("s", a.s); put("fp", a.fp) })
            put("cert", buildJsonObject { put("b", cert.b); put("s", cert.s) })
            put("safety", safetyNumber(o.fp, a.fp))
            put("backup", buildJsonObject { put("user", "alice"); put("passphrase", passphrase); put("pepper", b64(pepper)); put("sealed", sealed); put("payload", payload) })
            put("epoch", buildJsonObject { put("room", room); put("epoch", 1); put("from", "dcx-admin"); put("h", ep.pkg.h); put("s", ep.pkg.s)
                                           put("w_alice", ep.pkg.w.getValue("alice")); put("key_sha3", hex(sha3_256(ep.key))) })
            put("message", buildJsonObject { put("room", room); put("epoch", 1); put("from", "dcx-admin"); put("h", msg.h); put("c", msg.c); put("s", msg.s); put("text", text) })
        }
        // Fresh randomness every run: into the build folder, and into the committed fixtures only on purpose
        // (CIPHERCHAT_WRITE_FIXTURES=1, docs/INTEROP.md), so a release never picks up an unchecked one
        val out = if (System.getenv("CIPHERCHAT_WRITE_FIXTURES") == "1") dir else File("build/interop-made").apply { mkdirs() }
        File(out, "phone-made.json").writeText(fixture.toString())
        // sanity: the phone opens its own fixture too
        assertEquals(text, Room.openMessage(room, 1, "dcx-admin", msg.h, msg.c, msg.s,
            Room.openEpoch(alice, a.fp, room, 1, "dcx-admin", ep.pkg.h, ep.pkg.s, ep.pkg.w["alice"], oPub).key, oPub).text)
    }
}
