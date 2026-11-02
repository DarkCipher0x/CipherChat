package systems.darkcipher.cipherchat.client

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import systems.darkcipher.cipherchat.crypto.Devices
import systems.darkcipher.cipherchat.crypto.b64
import systems.darkcipher.cipherchat.crypto.hex
import systems.darkcipher.cipherchat.crypto.random
import java.io.File

/** Prekey seeds in the key store (PROTOCOL.md §11): sealed like room keys, kept apart from them, gone once dropped. */
class PrekeyStoreTest {
    private object PlainGuard : StoreGuard {
        override fun protect(plain: ByteArray) = plain.copyOf()
        override fun unprotect(sealed: ByteArray) = sealed.copyOf()
    }

    @Test fun prekeysAreSealedKeptApartAndErased() {
        val dir = File("build/prekey-store-" + hex(random(6))).apply { mkdirs() }
        val file = File(dir, "store.bin")
        val sk = Devices.storeKey(random(32), "alice")
        try {
            val s = KeyStore.open(file, PlainGuard, "alice", sk, "Test phone")
            val seed = Devices.newSeed()
            s.putPrekey("00000000000000aa", seed, 5000)
            s.put("0123456789abcdef", 1, random(32), 1)
            assertEquals(1, s.list().size)                                   // room keys only
            assertFalse(file.readText().contains(b64(seed)))                 // sealed, never plain
            s.close()

            val again = KeyStore.open(file, PlainGuard, "alice", sk, "Test phone")
            assertEquals(listOf("00000000000000aa" to 5000L), again.listPrekeys())
            assertArrayEquals(seed, again.getPrekey("00000000000000aa"))
            assertNull(again.getPrekey("00000000000000bb"))
            again.dropPrekeys(listOf("00000000000000aa"))
            assertTrue(again.listPrekeys().isEmpty())
            again.close()
            assertTrue(KeyStore.open(file, PlainGuard, "alice", sk, "Test phone").listPrekeys().isEmpty())
        } finally { dir.deleteRecursively() }
    }
}
