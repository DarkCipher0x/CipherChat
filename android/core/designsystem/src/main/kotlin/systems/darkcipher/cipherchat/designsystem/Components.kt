package systems.darkcipher.cipherchat.designsystem

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Status colours shared by every feature so "up/warn/down" always reads the same. */
enum class DcxStatus(val color: @Composable () -> Color) {
    Good({ DcxPalette.Good }),
    Warn({ DcxPalette.Warn }),
    Bad({ DcxPalette.Bad }),
    Idle({ MaterialTheme.colorScheme.onSurfaceVariant }),
}

/** A small coloured dot + label, used in lists and tiles. */
@Composable
fun StatusPill(status: DcxStatus, label: String, modifier: Modifier = Modifier) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Box(Modifier.size(8.dp).background(status.color(), CircleShape))
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** A bordered panel — the base surface for cards across the app (hairline teal border, soft radius). */
@Composable
fun DcxPanel(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Box(
        modifier
            .background(dcx().surface.copy(alpha = 0.82f), RoundedCornerShape(14.dp))
            .border(BorderStroke(1.dp, dcx().line), RoundedCornerShape(14.dp)),
    ) { content() }
}

/** A short uppercase mono section header, like a terminal section marker. */
@Composable
fun DcxSectionHeader(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        modifier = modifier.padding(horizontal = 4.dp, vertical = 6.dp),
        style = MaterialTheme.typography.labelMedium.copy(
            fontFamily = FontFamily.Monospace, letterSpacing = 2.sp, fontSize = 11.sp,
        ),
        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.8f),
    )
}

/**
 * A large, easy-to-hit action tile (minimum 96 dp, full-width tap target) — the primary way to launch a tool or open
 * a host facet. Icon in a tinted accent chip, title, and a one-line hint.
 */
@Composable
fun DcxActionTile(
    title: String,
    hint: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    accentIcon: Boolean = true,
    status: DcxStatus? = null,
) {
    val accent = MaterialTheme.colorScheme.primary
    Card(
        onClick = onClick,
        modifier = modifier.fillMaxWidth().heightIn(min = 92.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = dcx().surface.copy(alpha = 0.82f)),
        border = BorderStroke(1.dp, dcx().line),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Box(
                    Modifier.size(38.dp)
                        .background(accent.copy(alpha = if (accentIcon) 0.14f else 0.0f), RoundedCornerShape(10.dp)),
                    contentAlignment = Alignment.Center,
                ) { Icon(icon, null, tint = accent, modifier = Modifier.size(22.dp)) }
                Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                if (status != null) Box(Modifier.size(10.dp).background(status.color(), CircleShape))
            }
            Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

/**
 * A HUD metric tile (title, big value, status). Used on the home overview.
 */
@Composable
fun DcxTile(
    title: String,
    value: String,
    icon: ImageVector,
    status: DcxStatus = DcxStatus.Idle,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val accent = MaterialTheme.colorScheme.primary
    Card(
        onClick = onClick,
        modifier = modifier.fillMaxWidth().heightIn(min = 96.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = dcx().surface.copy(alpha = 0.82f)),
        border = BorderStroke(1.dp, dcx().line),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(icon, null, tint = accent, modifier = Modifier.size(20.dp))
                Text(title.uppercase(), style = MaterialTheme.typography.labelMedium.copy(
                    fontFamily = FontFamily.Monospace, letterSpacing = 1.sp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(value, style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface)
            StatusPill(status, when (status) {
                DcxStatus.Good -> "OK"
                DcxStatus.Warn -> "Check"
                DcxStatus.Bad -> "Problem"
                DcxStatus.Idle -> "—"
            })
        }
    }
}
