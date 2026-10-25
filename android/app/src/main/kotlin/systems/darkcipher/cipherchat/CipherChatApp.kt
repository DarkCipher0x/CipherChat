package systems.darkcipher.cipherchat

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import systems.darkcipher.cipherchat.call.CallBridge
import systems.darkcipher.cipherchat.crypto.SelfTest

/**
 * The process: one [Session], the background connection while the chat is unlocked ([ChatService]), and auto-lock:
 * once no CipherChat screen has been visible for the chosen number of minutes (and no call is on), every key is wiped
 * and the next open needs the fingerprint or screen lock again.
 */
class CipherChatApp : Application() {
    lateinit var session: Session; private set
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    /** The cryptography known-answer self-test (started at launch): null if it passed, else what failed. The app
     *  refuses to unlock if it fails. */
    lateinit var selfTest: Deferred<String?>; private set
    private var visible = 0
    private val main = Handler(Looper.getMainLooper())
    private val autoLock = Runnable { if (CallBridge.inCall) rescheduleLock() else session.lockAll() }

    override fun onCreate() {
        super.onCreate()
        selfTest = scope.async(Dispatchers.Default) { SelfTest.run().filter { !it.ok }.joinToString("; ") { it.name }.ifEmpty { null } }
        session = Session(filesDir, BuildConfig.DEBUG)
        Notifications.channels(this)
        CallBridge.secure = !BuildConfig.DEBUG
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityCreated(a: Activity, b: Bundle?) {
                // never in screenshots, the recents thumbnail or screen casts (debug builds stay reviewable)
                if (!BuildConfig.DEBUG) a.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            }
            override fun onActivityStarted(a: Activity) { visible++; main.removeCallbacks(autoLock) }
            override fun onActivityStopped(a: Activity) { visible--; if (visible <= 0) rescheduleLock() }
            override fun onActivityResumed(a: Activity) {}
            override fun onActivityPaused(a: Activity) {}
            override fun onActivitySaveInstanceState(a: Activity, b: Bundle) {}
            override fun onActivityDestroyed(a: Activity) {}
        })
        // the background connection runs exactly while the chat is unlocked
        scope.launch {
            session.stage.collectLatest { st ->
                if (st == Session.Stage.Chat) ChatService.start(this@CipherChatApp) else ChatService.stop(this@CipherChatApp)
                if (st == Session.Stage.VaultLocked) Notifications.clearAll(this@CipherChatApp)
            }
        }
    }

    val inForeground get() = visible > 0

    private fun rescheduleLock() {
        main.removeCallbacks(autoLock)
        if (session.stage.value == Session.Stage.VaultLocked) return
        main.postDelayed(autoLock, session.saved.autoLockMinutes.coerceAtLeast(1) * 60_000L)
    }
}
