package systems.darkcipher.cipherchat.call

import android.Manifest
import android.annotation.SuppressLint
import android.app.PictureInPictureParams
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.util.Rational
import android.view.WindowManager
import android.webkit.PermissionRequest
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.lifecycleScope
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.client.CallListener
import systems.darkcipher.cipherchat.client.ChatEngine
import systems.darkcipher.cipherchat.client.IncomingCall
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.designsystem.DarkCipherTheme
import systems.darkcipher.cipherchat.designsystem.DcxPalette
import systems.darkcipher.cipherchat.designsystem.DcxRoot
import systems.darkcipher.cipherchat.designsystem.dcx

/**
 * A voice or video call (docs/CALLS.md). Ringing is native (no WebView runs until the call is answered). The call
 * itself is the shared call page in a WebView that can load only its own files from the APK
 * (https://appassets.androidplatform.net/callhost/), can't navigate anywhere, gets the camera and microphone only for
 * that page, and talks to the app only through an origin-restricted message channel; signing, verifying and key
 * wrapping happen in core:client with the identity, and signals travel over the app's PQ-only TLS.
 */
class CallActivity : ComponentActivity() {
    private var engine: ChatEngine? = null
    private var web: WebView? = null
    private var page: JavaScriptReplyProxy? = null
    private var first: (() -> Unit)? = null
    private var ended = false
    private var video = false
    private var ring by mutableStateOf<IncomingCall?>(null)
    private var webMode by mutableStateOf(false)
    private var proximity: PowerManager.WakeLock? = null
    private val audio by lazy { getSystemService(AudioManager::class.java) }

    private val listener = object : CallListener {
        override fun signals(items: JsonArray) = runOnUiThread { post("signals", buildJsonObject { put("items", items) }) }
        override fun ringStopped(call: String, why: String) = runOnUiThread {
            if (ring?.call == call && !webMode) { Toast.makeText(this@CallActivity, "Call $why", Toast.LENGTH_SHORT).show(); finish() }
        }
    }

    private val askPermissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { got ->
        if (got[Manifest.permission.RECORD_AUDIO] == false && !has(Manifest.permission.RECORD_AUDIO)) {
            Toast.makeText(this, "CipherChat needs the microphone for calls.", Toast.LENGTH_LONG).show()
            ring?.let { engine?.calls?.decline(it) }
            finish()
        } else openWeb()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val e = CallBridge.engine
        if (e == null || CallBridge.inCall) { finish(); return }             // one call at a time (a ring meanwhile gets "busy")
        engine = e
        e.calls.addListener(listener)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val mode = intent.getStringExtra(EXTRA_MODE)
        if (mode == MODE_RING || mode == MODE_ANSWER) {
            // only a call that is verified and still ringing here (the engine's own record, not the intent's word)
            val r = e.calls.ringingCall(intent.getStringExtra(EXTRA_CALL) ?: "")
            if (r == null) { Toast.makeText(this, "That call has ended.", Toast.LENGTH_SHORT).show(); finish(); return }
            setShowWhenLocked(true); setTurnScreenOn(true)
            ring = r
            video = r.media == "video"
            if (mode == MODE_ANSWER) answer(r)                                 // "Answer" on the notification
        } else {
            video = intent.getStringExtra(EXTRA_MEDIA) == "video"
            val room = intent.getStringExtra(EXTRA_ROOM) ?: run { finish(); return }
            val people = intent.getStringArrayListExtra(EXTRA_PEOPLE) ?: arrayListOf()
            first = { post("start", buildJsonObject { put("room", room); put("media", if (video) "video" else "audio"); put("people", strings(people)) }) }
            requestMedia()
        }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = hangUp()
        })
        setContent {
            DarkCipherTheme {
                DcxRoot {
                    val r = ring
                    if (webMode) AndroidView(factory = { web!! }, modifier = Modifier.fillMaxSize().safeDrawingPadding())   // clear of the status and navigation bars
                    else if (r != null) RingScreen(r, onAnswer = { answer(r) }, onDecline = { engine?.calls?.decline(r); finish() })
                }
            }
        }
    }

    /** "Answer" on the notification while the ring screen is already up. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val r = ring
        if (intent.getStringExtra(EXTRA_MODE) == MODE_ANSWER && r != null && !webMode && intent.getStringExtra(EXTRA_CALL) == r.call) answer(r)
    }

    private fun strings(l: List<String>) = buildJsonArray { l.forEach { add(JsonPrimitive(it)) } }

    private fun has(p: String) = checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED

    private fun requestMedia() {
        val want = listOfNotNull(Manifest.permission.RECORD_AUDIO, if (video) Manifest.permission.CAMERA else null).filter { !has(it) }
        if (want.isEmpty()) openWeb() else askPermissions.launch(want.toTypedArray())
    }

    private fun answer(r: IncomingCall) {
        val e = engine ?: return
        first = { post("answer", buildJsonObject { put("call", r.call); put("items", e.calls.open(r.call)) }) }
        requestMedia()
    }

    // ------------------------------------------------------------------------------------------- the WebView
    @SuppressLint("SetJavaScriptEnabled")
    private fun openWeb() {
        val e = engine ?: return finish()
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            Toast.makeText(this, "Calls need a newer Android System WebView. Update it from the Play Store.", Toast.LENGTH_LONG).show()
            ring?.let { e.calls.decline(it) }
            return finish()
        }
        CallBridge.inCall = true
        startAudio()
        WebView.setWebContentsDebuggingEnabled(!CallBridge.secure)
        // https://appassets.androidplatform.net/callhost/<file> -> the APK's assets/callhost/<file> (and nothing else)
        val assets = WebViewAssetLoader.AssetsPathHandler(this)
        val loader = WebViewAssetLoader.Builder().addPathHandler("/callhost/") { path -> assets.handle("callhost/$path") }.build()
        val w = WebView(this)
        w.settings.apply {
            javaScriptEnabled = true
            mediaPlaybackRequiresUserGesture = false
            allowFileAccess = false
            allowContentAccess = false
            domStorageEnabled = false
            databaseEnabled = false
            setGeolocationEnabled(false)
            safeBrowsingEnabled = false                                       // only our own files load; nothing to look up
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
            saveFormData = false
        }
        w.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest): WebResourceResponse? =
                if (req.url.host == HOST) loader.shouldInterceptRequest(req.url) else WebResourceResponse("text/plain", "utf-8", 403, "Forbidden", emptyMap(), null)
            override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest) = true   // no navigation anywhere
        }
        w.webChromeClient = object : WebChromeClient() {
            override fun onPermissionRequest(request: PermissionRequest) {
                val ours = request.origin.scheme == "https" && request.origin.host == HOST
                val allowed = request.resources.filter {
                    (it == PermissionRequest.RESOURCE_AUDIO_CAPTURE && has(Manifest.permission.RECORD_AUDIO)) ||
                    (it == PermissionRequest.RESOURCE_VIDEO_CAPTURE && has(Manifest.permission.CAMERA))
                }
                if (ours && allowed.isNotEmpty()) request.grant(allowed.toTypedArray()) else request.deny()
            }
        }
        WebViewCompat.addWebMessageListener(w, "cipherchatHost", setOf(ORIGIN)) { _: WebView, msg: WebMessageCompat, source: Uri, main: Boolean, reply: JavaScriptReplyProxy ->
            if (!main || source.toString() != ORIGIN) return@addWebMessageListener
            page = reply
            val m = try { Json.parseToJsonElement(msg.data ?: "") as? JsonObject } catch (x: Exception) { null } ?: return@addWebMessageListener
            onMessage(e, m)
        }
        web = w
        webMode = true
        w.loadUrl("$ORIGIN/callhost/call.html")
    }

    private fun post(event: String, detail: JsonObject) {
        page?.postMessage(buildJsonObject { put("event", event); put("detail", detail) }.toString())
    }

    private fun onMessage(e: ChatEngine, m: JsonObject) {
        val ev = m.strOrNull("event")
        if (ev != null) { onEvent(e, ev, m["detail"] as? JsonObject ?: JsonObject(emptyMap())); return }
        lifecycleScope.launch {
            val reply = CallBridge.answer(e, m)
            if (reply.isNotEmpty()) page?.postMessage(reply.toString())
        }
    }

    private fun onEvent(e: ChatEngine, ev: String, d: JsonObject) {
        when (ev) {
            "ready" -> {
                post("init", buildJsonObject {
                    put("user", e.myUser); put("dev", e.calls.device)
                    put("labels", buildJsonObject { e.roomList.forEach { put(it.id, it.label(e.myUser)) } })
                    put("trusted", strings(e.calls.trustedUsers))
                    put("diag", false)
                    put("fakeMedia", !CallBridge.secure && intent.getBooleanExtra(EXTRA_FAKE_MEDIA, false))
                })
                first?.invoke()
                first = null
            }
            "notice" -> if (d.strOrNull("kind") == "err") Toast.makeText(this, d.strOrNull("text") ?: "", Toast.LENGTH_LONG).show()
            "ended" -> {
                if (ended) return
                ended = true
                Toast.makeText(this, "Call ended (" + (d.strOrNull("why") ?: "") + ").", Toast.LENGTH_SHORT).show()
                lifecycleScope.launch { delay(600); finish() }
            }
        }
    }

    private fun hangUp() {
        if (!webMode) { ring?.let { engine?.calls?.decline(it) }; finish(); return }
        if (ended) { finish(); return }
        post("hangup", JsonObject(emptyMap()))                                // hang up properly first; "ended" closes the screen
        lifecycleScope.launch { delay(3000); ended = true; finish() }
    }

    // ------------------------------------------------------------------------------------------- audio and the screen
    private fun startAudio() {
        audio.mode = AudioManager.MODE_IN_COMMUNICATION
        val speaker = audio.availableCommunicationDevices.firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
        val headset = audio.availableCommunicationDevices.firstOrNull { it.type in HEADSETS }
        when {
            headset != null -> audio.setCommunicationDevice(headset)
            video && speaker != null -> audio.setCommunicationDevice(speaker)
        }
        if (!video) {
            // voice calls: the screen goes dark against your ear, like a phone call
            val pm = getSystemService(PowerManager::class.java)
            if (pm.isWakeLockLevelSupported(PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK))
                proximity = pm.newWakeLock(PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK, "cipherchat:call").also { it.acquire(4 * 60 * 60 * 1000L) }
        }
        volumeControlStream = AudioManager.STREAM_VOICE_CALL
    }

    private fun stopAudio() {
        proximity?.let { if (it.isHeld) it.release() }
        proximity = null
        audio.clearCommunicationDevice()
        audio.mode = AudioManager.MODE_NORMAL
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        // leaving a video call keeps it going in a small window
        if (webMode && video && !ended) enterPictureInPictureMode(PictureInPictureParams.Builder().setAspectRatio(Rational(9, 16)).build())
    }

    override fun onDestroy() {
        engine?.calls?.removeListener(listener)
        if (webMode) {
            if (!ended) post("hangup", JsonObject(emptyMap()))
            engine?.calls?.closed()
            CallBridge.inCall = false
            stopAudio()
        }
        web?.destroy()
        web = null
        super.onDestroy()
    }

    companion object {
        private const val HOST = "appassets.androidplatform.net"
        private const val ORIGIN = "https://$HOST"
        private val HEADSETS = setOf(AudioDeviceInfo.TYPE_WIRED_HEADSET, AudioDeviceInfo.TYPE_WIRED_HEADPHONES, AudioDeviceInfo.TYPE_BLUETOOTH_SCO,
            AudioDeviceInfo.TYPE_USB_HEADSET, AudioDeviceInfo.TYPE_BLE_HEADSET)
        const val EXTRA_MODE = "mode"
        const val EXTRA_CALL = "call"
        const val EXTRA_ROOM = "room"
        const val EXTRA_MEDIA = "media"
        const val EXTRA_PEOPLE = "people"
        /** Debug builds only: the page draws its own camera and tone (emulator end-to-end runs). */
        const val EXTRA_FAKE_MEDIA = "fake_media"
        const val MODE_RING = "ring"
        const val MODE_ANSWER = "answer"
        const val MODE_START = "start"

        fun ringIntent(c: Context, inc: IncomingCall, answer: Boolean = false) = Intent(c, CallActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(EXTRA_MODE, if (answer) MODE_ANSWER else MODE_RING); putExtra(EXTRA_CALL, inc.call)
        }

        fun startIntent(c: Context, room: String, media: String, people: List<String>) = Intent(c, CallActivity::class.java).apply {
            putExtra(EXTRA_MODE, MODE_START); putExtra(EXTRA_ROOM, room); putExtra(EXTRA_MEDIA, media); putStringArrayListExtra(EXTRA_PEOPLE, ArrayList(people))
        }
    }
}

@Composable
private fun RingScreen(r: IncomingCall, onAnswer: () -> Unit, onDecline: () -> Unit) {
    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceBetween) {
        Column(Modifier.padding(top = 64.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(if (r.media == "video") "INCOMING VIDEO CALL" else "INCOMING VOICE CALL", style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.primary)
            Text(r.from, style = MaterialTheme.typography.displaySmall)
            val others = r.people.filter { it != r.from }
            if (others.size > 1) Text("with " + others.joinToString(", "), color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("End-to-end encrypted · ML-KEM-1024 + X25519", style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = dcx().muted)
        }
        Row(Modifier.fillMaxWidth().padding(bottom = 48.dp), horizontalArrangement = Arrangement.SpaceEvenly) {
            RoundAction("Decline", Icons.Filled.CallEnd, DcxPalette.Bad, onDecline)
            RoundAction("Answer", if (r.media == "video") Icons.Filled.Videocam else Icons.Filled.Call, DcxPalette.Good, onAnswer)
        }
    }
}

@Composable
private fun RoundAction(label: String, icon: androidx.compose.ui.graphics.vector.ImageVector, color: androidx.compose.ui.graphics.Color, onClick: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = onClick, modifier = Modifier.size(76.dp), shape = RoundedCornerShape(24.dp),
            colors = ButtonDefaults.buttonColors(containerColor = color)) {
            Icon(icon, label, tint = MaterialTheme.colorScheme.background, modifier = Modifier.size(32.dp))
        }
        Text(label)
    }
}
