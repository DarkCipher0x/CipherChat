package systems.darkcipher.cipherchat.designsystem

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CompletableDeferred

/**
 * Dialogs that code running anywhere (the chat engine asking for an authenticator code, a screen confirming a delete)
 * can await: [ask] suspends until the person answers. Render [Host] once at the app root.
 */
class DcxPrompts {
    class Request(val title: String, val message: String, val field: String?, val secret: Boolean, val numeric: Boolean,
                  val ok: String, val danger: Boolean, val error: String?, val answer: CompletableDeferred<String?>)

    private var current by mutableStateOf<Request?>(null)

    /** A text answer, or null if cancelled. */
    suspend fun ask(title: String, message: String, field: String, secret: Boolean = false, numeric: Boolean = false,
                    ok: String = "OK", error: String? = null): String? {
        val r = Request(title, message, field, secret, numeric, ok, false, error, CompletableDeferred())
        current = r
        return try { r.answer.await() } finally { if (current === r) current = null }
    }

    /** Yes / no. */
    suspend fun confirm(title: String, message: String, ok: String = "OK", danger: Boolean = false): Boolean {
        val r = Request(title, message, null, false, false, ok, danger, null, CompletableDeferred())
        current = r
        return try { r.answer.await() != null } finally { if (current === r) current = null }
    }

    /** "Confirm it's you": the current code from the authenticator app. */
    suspend fun code(error: String?): String? =
        ask("Confirm it's you", "Enter the current code from your authenticator app.", "6-digit code", numeric = true, ok = "Confirm", error = error)

    @Composable
    fun Host() {
        val r = current ?: return
        var text by remember(r) { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { r.answer.complete(null) },
            title = { Text(r.title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(r.message)
                    if (r.error != null) Text(r.error, color = DcxPalette.Bad)
                    if (r.field != null) OutlinedTextField(text, { text = it }, label = { Text(r.field) }, singleLine = true,
                        visualTransformation = if (r.secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
                        keyboardOptions = KeyboardOptions(keyboardType = when { r.numeric -> KeyboardType.NumberPassword; r.secret -> KeyboardType.Password; else -> KeyboardType.Text }))
                }
            },
            confirmButton = {
                TextButton(onClick = { r.answer.complete(if (r.field == null) "" else text.trim()) }, enabled = r.field == null || text.isNotBlank()) {
                    Text(r.ok, color = if (r.danger) DcxPalette.Bad else MaterialTheme.colorScheme.primary)
                }
            },
            dismissButton = { TextButton(onClick = { r.answer.complete(null) }) { Text("Cancel") } },
        )
    }
}
