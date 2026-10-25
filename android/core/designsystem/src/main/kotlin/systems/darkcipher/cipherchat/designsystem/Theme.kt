package systems.darkcipher.cipherchat.designsystem

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.Density
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// Corners follow Samsung One UI: moderate radii, never full pills. Matches DarkCipher Studio.
private val DcxShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

// Type ramp matching Studio: iOS-style large titles (bold, tight) and slightly larger body.
private val DcxType = Typography().run {
    val sans = FontFamily.SansSerif
    copy(
        displaySmall = displaySmall.copy(fontFamily = sans, fontWeight = FontWeight.Bold, fontSize = 34.sp, letterSpacing = (-0.5).sp),
        headlineMedium = headlineMedium.copy(fontFamily = sans, fontWeight = FontWeight.SemiBold),
        headlineSmall = headlineSmall.copy(fontFamily = sans, fontWeight = FontWeight.SemiBold),
        titleLarge = titleLarge.copy(fontFamily = sans, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.2).sp),
        titleMedium = titleMedium.copy(fontFamily = sans, fontWeight = FontWeight.SemiBold, fontSize = 17.sp),
        bodyLarge = bodyLarge.copy(fontFamily = sans, fontSize = 17.sp),
        bodyMedium = bodyMedium.copy(fontFamily = sans, fontSize = 15.sp),
        labelLarge = labelLarge.copy(fontFamily = sans, fontWeight = FontWeight.SemiBold, fontSize = 15.sp),
        labelMedium = labelMedium.copy(fontFamily = sans, fontWeight = FontWeight.Medium),
    )
}

/** Monospace for IPs, fingerprints, ports and command output — the terminal signature. */
val DcxMono = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp)

/** A smaller mono for dense tables and captions. */
val DcxMonoSmall = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp)

private fun DcxTheme.colorScheme() = if (dark) {
    darkColorScheme(
        primary = accent, onPrimary = onAccent,
        primaryContainer = hover, onPrimaryContainer = accent,
        secondary = accent, onSecondary = onAccent,
        secondaryContainer = surfaceRaised, onSecondaryContainer = foreground,
        tertiary = accent, onTertiary = onAccent,
        background = background, onBackground = foreground,
        surface = surface, onSurface = foreground,
        surfaceVariant = hover, onSurfaceVariant = muted,
        surfaceContainer = surface, surfaceContainerLow = surface,
        surfaceContainerHigh = surfaceRaised, surfaceContainerHighest = surfaceRaised,
        outline = line, outlineVariant = line,
        error = DcxPalette.Bad, onError = onAccent,
    )
} else {
    lightColorScheme(
        primary = accent, onPrimary = onAccent,
        primaryContainer = hover, onPrimaryContainer = accent,
        secondary = accent, onSecondary = onAccent,
        tertiary = accent, onTertiary = onAccent,
        background = background, onBackground = foreground,
        surface = surface, onSurface = foreground,
        surfaceVariant = hover, onSurfaceVariant = muted,
        surfaceContainer = surface, surfaceContainerLow = surface,
        surfaceContainerHigh = surfaceRaised, surfaceContainerHighest = surfaceRaised,
        outline = line, outlineVariant = line,
        error = DcxPalette.Bad, onError = onAccent,
    )
}

@Composable
fun DarkCipherTheme(content: @Composable () -> Unit) {
    val theme by DcxThemeStore.current.collectAsState()
    val size by DcxThemeStore.textSize.collectAsState()
    val scheme = theme.colorScheme()
    val d = LocalDensity.current
    // the app's text size setting scales every sp on top of Android's own font size
    CompositionLocalProvider(LocalDcxTheme provides theme, LocalDensity provides Density(d.density, d.fontScale * size / 100f)) {
        MaterialTheme(colorScheme = scheme, typography = DcxType, shapes = DcxShapes) {
            // Material only sets the content colour inside a Surface; our screens sit on a Box backdrop, so without
            // this any Text without an explicit colour would default to black. Default content to the foreground.
            CompositionLocalProvider(LocalContentColor provides scheme.onBackground, content = content)
        }
    }
}

/** Buttons follow Samsung One UI too: rounded corners, never full pills (Material's default). */
val DcxButtonShape = RoundedCornerShape(12.dp)
