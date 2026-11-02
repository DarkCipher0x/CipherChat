package systems.darkcipher.cipherchat.client

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The warning for wraps the server should have deleted (PREKEYS-DESIGN §4.2). */
class LeftoverWrapTest {
    @Test
    fun onlyWrapsKeptPastTheGracePeriodCount() {
        val now = System.currentTimeMillis() / 1000
        val day = 86400L
        fun item(at: Long, w: String?) = buildJsonObject {
            put("at", at)
            put("body", buildJsonObject { put("w", if (w == null) JsonNull else JsonPrimitive(w)) })
        }
        val items = JsonArray(listOf(item(now - 30 * day, "x"), item(now - 9 * day, "x"), item(now - 7 * day - day / 2, "x"),
                                     item(now - 30 * day, null), item(now, "x")))
        assertEquals(2, KeyHistory.leftover(items))
        assertTrue(KeyHistory.leftoverWarning(2).contains("2 copies"))
        assertTrue(KeyHistory.leftoverWarning(1).contains("1 copy "))
    }
}
