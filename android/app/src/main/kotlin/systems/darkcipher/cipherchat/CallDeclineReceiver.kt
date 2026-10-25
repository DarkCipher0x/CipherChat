package systems.darkcipher.cipherchat

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** "Decline" on the incoming-call notification: tells the caller (a signed "decline") without opening the app. */
class CallDeclineReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val calls = (context.applicationContext as CipherChatApp).session.engine?.calls
        val inc = calls?.ringingCall(intent.getStringExtra(EXTRA_CALL) ?: "")
        if (calls != null && inc != null) calls.decline(inc)
        Notifications.stopRinging(context)
    }

    companion object { const val EXTRA_CALL = "call" }
}
