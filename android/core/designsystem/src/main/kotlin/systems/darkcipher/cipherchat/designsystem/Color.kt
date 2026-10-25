package systems.darkcipher.cipherchat.designsystem

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Colours that never change with the theme, matched to DarkCipher Command and Studio so the whole app family looks
 * identical. Status colours stay fixed on purpose (as in ServerManagement): "failed" must look the same under every
 * theme. Everything else comes from the active [DcxTheme].
 */
object DcxPalette {
    val Good = Color(0xFF36D27A)
    val Warn = Color(0xFFE8C547)
    val Bad = Color(0xFFFF5F6D)

    /** The DarkCipher brand teal, for the brand mark whatever the theme. */
    val Brand = Color(0xFF36D2CB)
}

/**
 * One complete theme, the same across the DarkCipher Systems apps (Command, Studio, CipherChat). [wallpaper] is a
 * faint brand backdrop drawn behind the grid (null for the coloured themes, which read cleaner on plain dark).
 */
data class DcxTheme(
    val id: String,
    val name: String,
    val dark: Boolean,
    val background: Color,
    val surface: Color,
    val surfaceRaised: Color,
    val foreground: Color,
    val muted: Color,
    val line: Color,
    val hover: Color,
    val header: Color,
    val accent: Color,
    val onAccent: Color,
    val wallpaper: Int? = null,
    val grid: Boolean = true,
)

object DcxThemes {
    /** Default: the DarkCipher ServerManagement/Studio terminal palette, identical across the family. */
    val DarkCipher = DcxTheme(
        "darkcipher", "DarkCipher", true,
        background = Color(0xFF050909), surface = Color(0xFF0B1314), surfaceRaised = Color(0xFF101C1D),
        foreground = Color(0xFFD2F2EF), muted = Color(0xFF5A8986), line = Color(0xFF16302F), hover = Color(0xFF0F2122),
        header = Color(0xFF000000), accent = Color(0xFF36D2CB), onAccent = Color(0xFF000000),
        wallpaper = R.drawable.dcx_wall_minimal,
    )
    val Oled = DarkCipher.copy(
        id = "oled", name = "OLED black",
        background = Color(0xFF000000), surface = Color(0xFF070707), surfaceRaised = Color(0xFF0E0E0E),
        line = Color(0xFF1E1E1E), hover = Color(0xFF121212), muted = Color(0xFF7A8A89),
        wallpaper = R.drawable.dcx_wall_lock,
    )
    val Midnight = DcxTheme(
        "midnight", "Midnight", true,
        background = Color(0xFF070B14), surface = Color(0xFF0D1422), surfaceRaised = Color(0xFF131C2E),
        foreground = Color(0xFFDCE6F7), muted = Color(0xFF6C7FA3), line = Color(0xFF1C2840), hover = Color(0xFF111A2B),
        header = Color(0xFF03060C), accent = Color(0xFF5B9BFF), onAccent = Color(0xFF000000),
        wallpaper = R.drawable.dcx_wall_network,
    )
    val Ember = DcxTheme(
        "ember", "Ember", true,
        background = Color(0xFF0C0806), surface = Color(0xFF16100C), surfaceRaised = Color(0xFF1E1610),
        foreground = Color(0xFFF5E6D8), muted = Color(0xFF9A7E68), line = Color(0xFF2E2219), hover = Color(0xFF1A130E),
        header = Color(0xFF050302), accent = Color(0xFFFFA24C), onAccent = Color(0xFF000000),
    )
    val Violet = DcxTheme(
        "violet", "Violet", true,
        background = Color(0xFF0A0710), surface = Color(0xFF130E1C), surfaceRaised = Color(0xFF1A1426),
        foreground = Color(0xFFEDE3FA), muted = Color(0xFF8C7AA8), line = Color(0xFF2A2140), hover = Color(0xFF17112A),
        header = Color(0xFF040208), accent = Color(0xFFB58CFF), onAccent = Color(0xFF000000),
    )
    val HighContrast = DcxTheme(
        "contrast", "High contrast", true,
        background = Color(0xFF000000), surface = Color(0xFF000000), surfaceRaised = Color(0xFF111111),
        foreground = Color(0xFFFFFFFF), muted = Color(0xFFCCCCCC), line = Color(0xFF2A2A2A), hover = Color(0xFF222222),
        header = Color(0xFF000000), accent = Color(0xFF00FFF0), onAccent = Color(0xFF000000), grid = false,
        wallpaper = R.drawable.dcx_wall_lock,
    )
    val Light = DcxTheme(
        "light", "Daylight", false,
        background = Color(0xFFF1F6F6), surface = Color(0xFFFFFFFF), surfaceRaised = Color(0xFFE3EDED),
        foreground = Color(0xFF08191A), muted = Color(0xFF4E6E6C), line = Color(0xFFBCD2D1), hover = Color(0xFFD5E5E5),
        header = Color(0xFFE3EDED), accent = Color(0xFF0E8C86), onAccent = Color(0xFFFFFFFF), grid = false,
    )

    val all = listOf(DarkCipher, Oled, Midnight, Ember, Violet, HighContrast, Light)
    fun byId(id: String?): DcxTheme = all.firstOrNull { it.id == id } ?: DarkCipher
}

/** Holds the chosen theme, persisted in plain preferences (a cosmetic choice, not a secret). */
object DcxThemeStore {
    private const val PREF = "cipherchat_theme"
    private const val KEY = "id"
    private val _current = MutableStateFlow(DcxThemes.DarkCipher)
    val current: StateFlow<DcxTheme> = _current.asStateFlow()

    fun load(context: Context) {
        val id = context.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString(KEY, null)
        _current.value = DcxThemes.byId(id)
    }

    fun select(context: Context, id: String) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit().putString(KEY, id).apply()
        _current.value = DcxThemes.byId(id)
    }

    /** The app's own text size (percent), on top of Android's font size setting. One number, nothing secret. */
    val textSizes = listOf(90, 100, 110, 125, 140, 160, 180, 200)
    private const val SIZE_KEY = "text_size"
    private val _textSize = MutableStateFlow(100)
    val textSize: StateFlow<Int> = _textSize.asStateFlow()

    fun loadTextSize(context: Context) {
        val p = context.getSharedPreferences(PREF, Context.MODE_PRIVATE).getInt(SIZE_KEY, 100)
        _textSize.value = if (p in textSizes) p else 100
    }

    fun selectTextSize(context: Context, percent: Int) {
        if (percent !in textSizes) return
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit().putInt(SIZE_KEY, percent).apply()
        _textSize.value = percent
    }
}

val LocalDcxTheme = staticCompositionLocalOf { DcxThemes.DarkCipher }

/** The active theme, for any composable under DarkCipherTheme. */
val dcxTheme: DcxTheme
    @Composable @ReadOnlyComposable get() = LocalDcxTheme.current

@Composable
@ReadOnlyComposable
fun dcx(): DcxTheme = LocalDcxTheme.current
