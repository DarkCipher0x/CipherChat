package systems.darkcipher.cipherchat.chat

import android.graphics.ImageDecoder
import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DcxMonoSmall
import systems.darkcipher.cipherchat.designsystem.dcx
import java.nio.ByteBuffer

/** The emoji picker: the same curated set as the web chat and the Windows app (EmojiSets, generated), with search. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun EmojiPicker(onPick: (String) -> Unit, onDismiss: () -> Unit) {
    var q by remember { mutableStateOf("") }
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 12.dp)) {
            OutlinedTextField(q, { q = it }, Modifier.fillMaxWidth(), placeholder = { Text("Search emoji") }, singleLine = true)
            val query = q.trim().lowercase()
            val shown = EmojiSets.all.filter { query.isEmpty() || it.second.contains(query) }
            LazyVerticalGrid(GridCells.Adaptive(46.dp), Modifier.fillMaxWidth().heightIn(max = 420.dp).padding(top = 8.dp)) {
                var cat: String? = null
                shown.forEach { (e, name, c) ->
                    if (query.isEmpty() && c != cat) {
                        cat = c
                        item(span = { GridItemSpan(maxLineSpan) }) {
                            Text(c.uppercase(), Modifier.padding(top = 8.dp, bottom = 2.dp), style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    item {
                        Text(e, Modifier.size(46.dp).clickable { onPick(e) }.padding(top = 6.dp), fontSize = 26.sp, textAlign = TextAlign.Center)
                    }
                }
                if (shown.isEmpty()) item(span = { GridItemSpan(maxLineSpan) }) { Text("No emoji match.", Modifier.padding(8.dp)) }
            }
        }
    }
}

/** The GIF sheet: the GIFs of this session (to send one again), and "Choose a GIF" from files. No GIF service is used. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun GifPicker(model: ChatModel, onPick: (String, ByteArray) -> Unit, onChoose: () -> Unit, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 12.dp).padding(bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("GIFS FROM THIS SESSION", style = DcxMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (model.gifs.isEmpty()) Text("None yet. GIFs you send, and GIFs that play in your rooms, show up here so you can send them again. Your keyboard's GIF button works too.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            else LazyVerticalGrid(GridCells.Fixed(3), Modifier.fillMaxWidth().heightIn(max = 360.dp), horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)) {
                items(model.gifs, key = { it.first + ":" + it.second.size }) { (name, bytes) ->
                    val still by produceState<android.graphics.Bitmap?>(null, bytes) {
                        value = withContext(Dispatchers.Default) {
                            try { ImageDecoder.decodeBitmap(ImageDecoder.createSource(ByteBuffer.wrap(bytes))) { d, _, _ -> d.setTargetSampleSize(2) } } catch (x: Exception) { null }
                        }
                    }
                    val b = still
                    Column(Modifier.aspectRatio(1f).border(1.dp, dcx().line, RoundedCornerShape(10.dp)).clickable { onPick(name, bytes) },
                        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                        if (b != null) Image(b.asImageBitmap(), "Send $name", Modifier.fillMaxWidth().aspectRatio(1f), contentScale = ContentScale.Crop)
                        else Text("GIF", style = DcxMonoSmall)
                    }
                }
            }
            OutlinedButton(onClick = onChoose, shape = DcxButtonShape) { Text("Choose a GIF…") }
            Text("End-to-end encrypted like any attachment. No GIF service sees what you search or send.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
