package systems.darkcipher.cipherchat.designsystem

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * Every screen sits in this: the DarkCipher terminal backdrop, a translucent top bar with a terminal "›" prefix and a
 * thin accent underline, and correct status/navigation-bar insets (the app draws edge to edge). [wallpaper] shows the
 * brand backdrop; turn it off for dense screens that need a plain base.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DcxScaffold(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
    wallpaper: Boolean = true,
    bottomBar: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    val accent = MaterialTheme.colorScheme.primary
    // The terminal backdrop is drawn once at the app root (DcxRoot); screens are transparent over it, so navigating
    // animates only lightweight content, not a full-screen image + grid per screen. [wallpaper] is kept for source
    // compatibility and is a no-op now.
    Scaffold(
        containerColor = Color.Transparent,
        bottomBar = bottomBar,
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("›", color = accent, fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold, modifier = Modifier.padding(end = 8.dp))
                            Text(title)
                        }
                    },
                    navigationIcon = {
                        if (onBack != null) {
                            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") }
                        }
                    },
                    actions = { actions() },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = dcx().header.copy(alpha = 0.72f),
                        titleContentColor = MaterialTheme.colorScheme.onSurface,
                        navigationIconContentColor = accent,
                        actionIconContentColor = accent,
                    ),
                )
                HorizontalDivider(color = accent.copy(alpha = 0.35f), thickness = 1.dp)
            }
        },
    ) { inner -> Box(Modifier.fillMaxSize().padding(inner)) { content(inner) } }
}

/** The single app-wide terminal backdrop. Wrap the whole UI once so screen transitions stay light. */
@Composable
fun DcxRoot(content: @Composable () -> Unit) {
    DcxBackground(showWallpaper = true, wallpaperAlpha = 0.08f) { content() }
}

