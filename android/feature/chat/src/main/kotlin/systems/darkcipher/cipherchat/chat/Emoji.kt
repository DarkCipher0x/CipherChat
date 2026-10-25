package systems.darkcipher.cipherchat.chat

import android.content.Context
import android.icu.lang.UCharacter
import android.icu.lang.UProperty
import android.icu.text.BreakIterator
import android.provider.Settings

/** GIFs bigger than this show their still preview; tapping opens the picture. */
internal const val GIF_INLINE_MAX = 16L * 1024 * 1024

/** True when the text is only 1-3 emoji (and spaces): the chat shows those big. Whole emoji sequences count once. */
internal fun isJumbo(s: String): Boolean {
    val t = s.trim()
    if (t.isEmpty() || t.length > 60) return false
    val it = BreakIterator.getCharacterInstance()
    it.setText(t)
    var n = 0
    var start = it.first()
    var end = it.next()
    while (end != BreakIterator.DONE) {
        val g = t.substring(start, end)
        if (g.isNotBlank()) { if (!isEmoji(g)) return false; n++ }
        start = end
        end = it.next()
    }
    return n in 1..3
}

private fun isEmoji(g: String): Boolean {
    if (g.contains('️') || g.contains('⃣')) return true
    val cp = g.codePointAt(0)
    return UCharacter.hasBinaryProperty(cp, UProperty.EMOJI_PRESENTATION) || UCharacter.hasBinaryProperty(cp, UProperty.REGIONAL_INDICATOR)
}

/** False when the phone's animations are off (Accessibility > Remove animations): GIFs then stay still. */
internal fun animationsOn(ctx: Context): Boolean =
    Settings.Global.getFloat(ctx.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0f
