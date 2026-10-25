package systems.darkcipher.cipherchat

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import systems.darkcipher.cipherchat.call.CallActivity
import systems.darkcipher.cipherchat.chat.ChatHome
import systems.darkcipher.cipherchat.chat.ChatHost
import systems.darkcipher.cipherchat.client.Room
import systems.darkcipher.cipherchat.designsystem.DcxButtonShape
import systems.darkcipher.cipherchat.designsystem.DarkCipherTheme
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxPrompts
import systems.darkcipher.cipherchat.designsystem.DcxRoot
import systems.darkcipher.cipherchat.designsystem.DcxThemeStore
import systems.darkcipher.cipherchat.gate.ConnectActions
import systems.darkcipher.cipherchat.gate.ConnectScreen
import systems.darkcipher.cipherchat.gate.GateScreen
import systems.darkcipher.cipherchat.gate.SavedPairing
import systems.darkcipher.cipherchat.security.Biometric
import java.net.URI

/**
 * The single chat activity: the vault prompt, then connect, then the gate (passphrase and owner check), then the chat.
 * Calls run in their own activity (feature:call).
 */
class MainActivity : FragmentActivity() {
    private val app get() = application as CipherChatApp
    private val session get() = app.session
    private val prompts = DcxPrompts()
    private var vaultError by mutableStateOf<String?>(null)
    private var openRoom by mutableStateOf<String?>(null)
    private var savedRev by mutableStateOf(0)
    private val notifyPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        DcxThemeStore.load(this)
        DcxThemeStore.loadTextSize(this)
        session.passkeys = Passkeys(this)
        openRoom = intent.getStringExtra(EXTRA_ROOM)
        setContent {
            DarkCipherTheme {
                DcxRoot {
                    val stage by session.stage.collectAsState()
                    when (stage) {
                        Session.Stage.VaultLocked -> VaultScreen()
                        Session.Stage.Connect -> Connect()
                        Session.Stage.Gate -> Gate()
                        Session.Stage.Chat -> Chat()
                    }
                    prompts.Host()
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        openRoom = intent.getStringExtra(EXTRA_ROOM)
    }

    override fun onResume() {
        super.onResume()
        session.passkeys = Passkeys(this)
    }

    // ------------------------------------------------------------------------------------------- stages
    private fun unlockVault() {
        lifecycleScope.launch {
            vaultError = try {
                app.selfTest.await()?.let { throw IllegalStateException("This phone's cryptography failed its self-test ($it), so CipherChat won't run.") }
                session.unlockVault(this@MainActivity)
                if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                    notifyPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                null
            } catch (e: Biometric.AuthError) { if (e.cancelled) null else e.message }
            catch (e: Exception) { e.message ?: "Not unlocked" }
        }
    }

    @Composable
    private fun VaultScreen() {
        Column(Modifier.fillMaxSize().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically)) {
            Icon(Icons.Filled.Fingerprint, null, Modifier.size(72.dp), tint = MaterialTheme.colorScheme.primary)
            Text("CipherChat", style = MaterialTheme.typography.displaySmall)
            Text("by DarkCipher Systems", color = MaterialTheme.colorScheme.onSurfaceVariant)
            when (Biometric.readiness(this@MainActivity)) {
                Biometric.Readiness.NoScreenLock -> Text("Set a screen lock (and ideally a fingerprint) first: CipherChat keeps its pairings in this phone's secure hardware, behind it.", color = DcxPalette.Warn)
                else -> Button(shape = DcxButtonShape, onClick = { unlockVault() }) { Text(if (session.vault.exists) "Unlock" else "Set up") }
            }
            vaultError?.let { Text(it, color = DcxPalette.Bad) }
        }
    }

    @Composable
    private fun Connect() {
        @Suppress("UNUSED_VARIABLE") val r = savedRev
        val saved = session.saved.servers
        ConnectScreen(saved.map { SavedPairing(it.user + "@" + it.name, it.origin) }, BuildConfig.DEBUG, object : ConnectActions {
            override suspend fun resume(index: Int) = session.resume(saved[index])
            override fun forget(index: Int) { session.forget(saved[index]); savedRev++ }
            override suspend fun pair(code: String) = session.pair(code)
            override suspend fun signIn(origin: String, user: String, password: String, code: String) = session.signIn(URI(origin.trimEnd('/')), user, password, code)
            override suspend fun passkey(origin: String) = session.passkeySignIn(URI(origin.trimEnd('/')))
        })
    }

    @Composable
    private fun Gate() {
        val api = session.api ?: return
        GateScreen(api, { session.state!! }, { session.refreshState() }, prompts::code,
            enter = { me -> session.start(me, prompts::code) },
            signOut = { session.signOut(false) },
            selfTest = null)
    }

    @Composable
    private fun Chat() {
        val e = session.engine ?: return
        ChatHome(e, host, openRoom)
    }

    private val host = object : ChatHost {
        override val prompts get() = this@MainActivity.prompts
        override val version = BuildConfig.VERSION_NAME
        override var autoLockMinutes: Int
            get() = session.saved.autoLockMinutes
            set(v) = session.setAutoLock(v)
        override fun startCall(room: Room, media: String, people: List<String>) {
            if (people.isEmpty()) return
            startActivity(CallActivity.startIntent(this@MainActivity, room.id, media, people))
        }
        override val pairedDevice get() = session.server != null
        override val fullScreenCalls get() = Notifications.fullScreenCallsAllowed(this@MainActivity)
        override fun allowFullScreenCalls() = Notifications.openFullScreenCallSettings(this@MainActivity)
        override fun lock() = session.lockAll()
        override suspend fun signOut(forgetPhone: Boolean) = session.signOut(forgetPhone)
        override fun viewing(room: Room?) { if (room != null) Notifications.clearMessages(this@MainActivity, room.id); openRoom = null }
    }

    companion object { const val EXTRA_ROOM = "room" }
}
