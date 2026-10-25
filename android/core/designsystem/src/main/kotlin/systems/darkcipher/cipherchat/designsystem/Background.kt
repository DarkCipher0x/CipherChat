package systems.darkcipher.cipherchat.designsystem

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp

/**
 * The signature DarkCipher terminal backdrop, matching Studio: the theme background, a faint brand wallpaper (when the
 * theme has one), a 40 dp accent grid and a soft accent glow from the top-left. Subtle enough not to compete with
 * content; it's what makes panels read as translucent and ties the app family together.
 */
@Composable
fun DcxBackground(
    modifier: Modifier = Modifier,
    showWallpaper: Boolean = true,
    wallpaperAlpha: Float = 0.08f,
    content: @Composable BoxScope.() -> Unit,
) {
    val theme = dcx()
    Box(modifier.fillMaxSize().background(theme.background)) {
        if (showWallpaper && theme.wallpaper != null) {
            Image(
                painter = painterResource(theme.wallpaper),
                contentDescription = null,
                modifier = Modifier.matchParentSize(),
                contentScale = ContentScale.Crop,
                alpha = wallpaperAlpha,
            )
        }
        Canvas(Modifier.matchParentSize()) {
            drawRect(
                brush = Brush.radialGradient(
                    colors = listOf(theme.accent.copy(alpha = 0.12f), Color.Transparent),
                    center = Offset(size.width * 0.15f, 0f),
                    radius = size.width * 1.05f,
                ),
            )
            if (theme.grid) {
                val step = 40.dp.toPx()
                val gl = theme.accent.copy(alpha = 0.035f)
                var x = 0f
                while (x <= size.width) {
                    drawLine(gl, Offset(x, 0f), Offset(x, size.height), 1f)
                    x += step
                }
                var y = 0f
                while (y <= size.height) {
                    drawLine(gl, Offset(0f, y), Offset(size.width, y), 1f)
                    y += step
                }
            }
        }
        content()
    }
}
