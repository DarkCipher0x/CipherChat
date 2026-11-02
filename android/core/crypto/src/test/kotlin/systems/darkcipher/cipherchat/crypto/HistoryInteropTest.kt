package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File

/**
 * Devices, the key store and history sync (PROTOCOL.md §10) across clients: browser-history.json (crypto.js) and
 * windows-history.json (BouncyCastle .NET) opened here; phone-history.json written for them, same rules as
 * [InteropTest] (the committed copy only with CIPHERCHAT_WRITE_FIXTURES=1).
 */
class HistoryInteropTest {
    private val dir = File("src/test/resources/interop")
    private fun JsonObject.o(k: String) = getValue(k).jsonObject
    private fun refused(f: () -> Unit) { assertThrows(CryptoFail::class.java) { f() } }

    /** What every client checks on a fixture any client made (the same list as web/tests/historytest.js). */
    private fun openFixture(f: JsonObject) {
        val master = fromHex(f.str("master"))
        val user = f.str("user")
        val id = identityFromMaster(user, master)
        val bundle = f.o("bundle")
        val at = Canon.parseSigned(bundle.str("b"), 16384).obj.long("at")
        assertEquals(f.str("fp"), publishIdentity(id, at).fp)
        val pub = openIdentity(bundle.str("b"), bundle.str("s"), user, f.str("fp"))
        val dl = f.o("devices")
        val list = Devices.open(Signed64(dl.str("b"), dl.str("s")), pub)
        assertEquals(1L, list.seq)
        assertEquals(2, list.devices.size)
        val to = Device.fromSeed(unb64(f.str("device_seed_to"), 96))
        val listed = list.devices.single { it.id == f.str("to") }
        assertEquals(listed.kemPq, b64(to.kemPqPk))
        assertEquals(listed.kemEc, b64(to.kemEcPk))
        assertEquals(f.str("code_to"), Devices.code(to.kemPqPk, to.kemEcPk))
        val keys = Devices.openKeySync(to, pub, f.str("from"), f.str("to"), f.str("sync_blob"))
        assertEquals(1, keys.size)
        assertEquals(f.str("room"), keys[0].room)
        assertEquals(f.str("room_key"), hex(keys[0].key))
        // the key passes the signed header's commitment without its wrap; a different key doesn't
        val e = f.o("epoch_item"); val body = e.o("body")
        Room.checkEpoch(f.str("room"), e.long("epoch"), e.str("from"), body.str("h"), body.str("s"), pub, keys[0].key)
        refused { Room.checkEpoch(f.str("room"), e.long("epoch"), e.str("from"), body.str("h"), body.str("s"), pub, random(32)) }
        refused { Devices.openKeySync(to, pub, f.str("from"), f.str("to"), f.str("sync_tampered")) }
        refused { Devices.openKeySync(to, pub, f.str("to"), f.str("from"), f.str("sync_blob")) }      // no replay between other devices
        refused { Devices.openKeySync(Device.fromSeed(Devices.newSeed()), pub, f.str("from"), f.str("to"), f.str("sync_blob")) }
        // the key store's double seal
        val st = f.o("store")
        val sk = Devices.storeKey(master, user)
        val dk = unb64(st.str("device_key"), 32)
        val sealed = unb64(st.str("sealed"))
        assertEquals(f.str("room_key"), hex(Devices.openStored(dk, sk, user, st.str("room"), st.long("epoch"), sealed)))
        refused { Devices.openStored(dk, sk, user, st.str("room"), 2, sealed) }
        refused { Devices.openStored(dk, Devices.storeKey(random(32), user), user, st.str("room"), st.long("epoch"), sealed) }
        val v = f["v2"] as? JsonObject ?: return             // made before protocol 2
        // protocol 2: prekeys and a per-device room key
        fun s64(k: String) = v.o(k).let { Signed64(it.str("b"), it.str("s")) }
        fun atOf(x: Signed64) = Canon.parseSigned(x.b, 4096, Canon.V2).obj.long("at")
        val ids = list.devices.map { it.id }
        val pkTo = s64("prekey_to")
        val pTo = Prekeys.open(pkTo, pub, ids, atOf(pkTo))
        val pre = Device.fromSeed(unb64(v.str("prekey_seed_to"), 96))
        assertEquals(f.str("to"), pTo.dev)
        assertEquals(b64(pre.kemPqPk), b64(pTo.kemPq))
        assertEquals(b64(pre.kemEcPk), b64(pTo.kemEc))
        Prekeys.open(s64("prekey_from"), pub, ids, atOf(pkTo))
        refused { Prekeys.open(pkTo, pub, listOf(f.str("from")), atOf(pkTo)) }                 // device not listed
        refused { Prekeys.open(pkTo, pub, ids, atOf(pkTo) + Prekeys.LIFE_MS) }                 // expired
        val mine = { pid: String -> if (pid == pTo.id) pre else null }
        val it2 = v.o("epoch_item"); val b2 = it2.o("body")
        fun open2(dev: String, w: String, of: (String) -> Device?) =
            Room.openEpochV2(id, f.str("fp"), dev, f.str("room"), it2.long("epoch"), it2.str("from"), b2.str("h"), b2.str("s"), w, pub, of)
        val e2 = open2(f.str("to"), b2.str("w"), mine)
        assertEquals(v.str("room_key"), hex(e2.key))
        assertEquals(2L, e2.header.long("v"))
        Room.checkEpoch(f.str("room"), it2.long("epoch"), it2.str("from"), b2.str("h"), b2.str("s"), pub, e2.key)
        refused { open2(f.str("to"), v.str("w_tampered"), mine) }
        refused { open2(f.str("from"), v.str("w_from"), mine) }
        refused { open2(f.str("to"), b2.str("w"), { null }) }
        refused { Room.openEpoch(id, f.str("fp"), f.str("room"), it2.long("epoch"), it2.str("from"), b2.str("h"), b2.str("s"), b2.str("w"), pub) }
    }

    private fun opens(name: String) {
        val file = File(dir, name)
        if (!file.exists()) return
        openFixture(Json.parseToJsonElement(file.readText()).jsonObject)
    }

    @Test fun phoneOpensTheBrowsersHistoryFixture() = opens("browser-history.json")
    @Test fun phoneOpensWindowsHistoryFixture() = opens("windows-history.json")

    @Test fun forgedAndMismatchedDeviceListsAreRefused() {
        val master = random(32)
        val id = identityFromMaster("alice", master)
        val p = publishIdentity(id, 1792800000000L)
        val pub = openIdentity(p.b, p.s, "alice")
        val dev = Device.fromSeed(Devices.newSeed())
        val ok = Devices.publish(id, p.fp, 1, listOf(Devices.entry("00000000000000ff", "Phone", dev, 1)), 2)
        assertEquals(1, Devices.open(ok, pub).devices.size)
        refused { Devices.open(Devices.publish(identityFromMaster("alice", random(32)), p.fp, 2, listOf(), 3), pub) }
        refused { Devices.open(Devices.publish(id, "0".repeat(64), 2, listOf(), 3), pub) }
        refused { Devices.open(Signed64(ok.b, Devices.publish(id, p.fp, 2, listOf(), 3).s), pub) }
        val dk = random(32); val sk = Devices.storeKey(master, "alice"); val seed = Devices.newSeed()
        val sealedSeed = Devices.sealSeed(dk, sk, "alice", seed)
        assertArrayEquals(seed, Devices.openSeed(dk, sk, "alice", sealedSeed))
        refused { Devices.openStored(dk, sk, "alice", "device", 0, sealedSeed) }       // wrong length for a room key
    }

    @Test fun phoneMakesAHistoryFixtureForTheOthers() {
        val at = 1792800000000L
        val user = "alice"; val room = "0123456789abcdef"
        val master = random(32)
        val id = identityFromMaster(user, master)
        val p = publishIdentity(id, at)
        val pub = openIdentity(p.b, p.s, user)
        val seedFrom = Devices.newSeed(); val seedTo = Devices.newSeed()
        val devFrom = Device.fromSeed(seedFrom); val devTo = Device.fromSeed(seedTo)
        val from = Devices.newId(); val to = Devices.newId()
        val list = Devices.publish(id, p.fp, 1, listOf(Devices.entry(from, "Old laptop", devFrom, 1790000000000L), Devices.entry(to, "New phone", devTo, 1790000000000L)), at)
        val ep = Room.buildEpoch(id, p.fp, room, 1, listOf(Room.Recipient(user, p.fp, pub)), "")
        val blob = Devices.sealKeySync(id, from, to, devTo.kemPqPk, devTo.kemEcPk, listOf(SyncedKey(room, 1, ep.key)), at)
        val tampered = unb64(blob).also { it[it.size - 20] = (it[it.size - 20].toInt() xor 1).toByte() }
        val deviceKey = random(32)
        val sealed = Devices.sealStored(deviceKey, Devices.storeKey(master, user), user, room, 1, ep.key)
        // protocol 2: a prekey for each device, and a per-device room key (epoch 2) wrapped to them
        val preSeedTo = Devices.newSeed()
        val preFrom = Device.fromSeed(Devices.newSeed()); val preTo = Device.fromSeed(preSeedTo)
        val pkFrom = Prekeys.publish(id, p.fp, from, Prekeys.newId(), preFrom, at)
        val pkTo = Prekeys.publish(id, p.fp, to, Prekeys.newId(), preTo, at)
        val ids = listOf(from, to)
        val e2 = Room.buildEpochV2(id, p.fp, room, 2, listOf(
            Room.DeviceLine(user, p.fp, to, Prekeys.open(pkTo, pub, ids, at)), Room.DeviceLine(user, p.fp, from, Prekeys.open(pkFrom, pub, ids, at))), "")
        val wTo = e2.pkg.w.getValue("$user|$to")
        val bad = unb64(wTo).also { it[it.size - 5] = (it[it.size - 5].toInt() xor 1).toByte() }
        val v2 = buildJsonObject {
            put("prekey_from", buildJsonObject { put("b", pkFrom.b); put("s", pkFrom.s) })
            put("prekey_to", buildJsonObject { put("b", pkTo.b); put("s", pkTo.s) })
            put("prekey_seed_to", b64(preSeedTo))
            put("epoch_item", buildJsonObject { put("epoch", 2); put("from", user); put("body", buildJsonObject { put("v", 2); put("h", e2.pkg.h); put("s", e2.pkg.s); put("w", wTo) }) })
            put("w_from", e2.pkg.w.getValue("$user|$from"))
            put("w_tampered", b64(bad))
            put("room_key", hex(e2.key))
        }
        val f = buildJsonObject {
            put("v", 1); put("made_by", "phone"); put("user", user); put("master", hex(master)); put("fp", p.fp)
            put("bundle", buildJsonObject { put("b", p.b); put("s", p.s) })
            put("devices", buildJsonObject { put("b", list.b); put("s", list.s) })
            put("from", from); put("to", to); put("v2", v2)
            put("device_seed_to", b64(seedTo)); put("code_to", Devices.code(devTo.kemPqPk, devTo.kemEcPk))
            put("room", room)
            put("epoch_item", buildJsonObject { put("epoch", 1); put("from", user); put("body", buildJsonObject { put("h", ep.pkg.h); put("s", ep.pkg.s) }) })
            put("room_key", hex(ep.key))
            put("sync_blob", blob); put("sync_tampered", b64(tampered))
            put("store", buildJsonObject { put("device_key", b64(deviceKey)); put("sealed", b64(sealed)); put("room", room); put("epoch", 1) })
        }
        openFixture(f)                 // the phone opens its own fixture by the same rules
        val out = if (System.getenv("CIPHERCHAT_WRITE_FIXTURES") == "1") dir else File("build/interop-made").apply { mkdirs() }
        File(out, "phone-history.json").writeText(f.toString())
    }
}
