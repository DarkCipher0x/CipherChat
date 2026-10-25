package systems.darkcipher.cipherchat

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import systems.darkcipher.cipherchat.client.CallListener
import systems.darkcipher.cipherchat.client.ChatEngine
import systems.darkcipher.cipherchat.client.ChatListener
import systems.darkcipher.cipherchat.client.IncomingCall

/**
 * Keeps the chat's connection (the long poll over PQ TLS) alive while the app is unlocked but not on screen, so
 * messages and calls still arrive. It runs only between unlocking and locking; locking (by hand or auto-lock) stops it
 * and wipes the keys. There is no push service: nothing about CipherChat passes through Google or anyone else.
 */
class ChatService : Service() {
    private val app get() = application as CipherChatApp
    private var engine: ChatEngine? = null
    private val notified = HashMap<String, Int>()

    // unread counts come from the engine (it skips the room on screen); a room read elsewhere loses its notification
    private val chat = object : ChatListener {
        override fun roomsChanged() {
            val e = engine ?: return
            for (r in e.roomList) synchronized(notified) {
                val before = notified[r.id] ?: 0
                if (r.unread == 0 && before > 0) { notified.remove(r.id); Notifications.clearMessages(this@ChatService, r.id) }
                else if (r.unread > before) {
                    notified[r.id] = r.unread
                    if (!app.inForeground) Notifications.message(this@ChatService, r.id, r.label(e.myUser), r.unread)
                }
            }
        }
    }

    private val calls = object : CallListener {
        override fun ringing(call: IncomingCall) {
            Notifications.ringing(this@ChatService, call)
            if (app.inForeground) startActivity(systems.darkcipher.cipherchat.call.CallActivity.ringIntent(this@ChatService, call))
        }
        override fun ringStopped(call: String, why: String) = Notifications.stopRinging(this@ChatService)
    }

    // A network came (back): queued messages are sent now instead of after the outbox's backoff
    private val network = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(n: Network) { engine?.networkChanged() }
        override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) {
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) engine?.networkChanged()
        }
    }

    override fun onCreate() {
        super.onCreate()
        try { getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(network) } catch (x: RuntimeException) { }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ServiceCompat.startForeground(this, Notifications.SERVICE_ID, Notifications.service(this, app.session.saved.autoLockMinutes),
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0)      // "specialUse" is Android 14+
        val e = app.session.engine
        if (e == null) { stopSelf(); return START_NOT_STICKY }
        if (e !== engine) {
            detach()
            engine = e
            e.addListener(chat)
            e.calls.addListener(calls)
        }
        return START_NOT_STICKY                                               // after the process dies the keys are gone anyway
    }

    private fun detach() {
        engine?.removeListener(chat)
        engine?.calls?.removeListener(calls)
        engine = null
    }

    override fun onDestroy() {
        try { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(network) } catch (x: RuntimeException) { }
        detach()
        super.onDestroy()
    }

    companion object {
        fun start(c: Context) = ContextCompat.startForegroundService(c, Intent(c, ChatService::class.java))
        fun stop(c: Context) { c.stopService(Intent(c, ChatService::class.java)) }
    }
}
