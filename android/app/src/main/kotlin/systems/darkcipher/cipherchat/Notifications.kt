package systems.darkcipher.cipherchat

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.RingtoneManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.Person
import systems.darkcipher.cipherchat.call.CallActivity
import systems.darkcipher.cipherchat.client.IncomingCall

/**
 * Notifications never carry message text or names of files: only "a new message in #room" (and who is calling), and
 * they're private on the lock screen. The text exists only inside the unlocked app.
 */
object Notifications {
    const val SERVICE = "service"
    private const val MESSAGES = "messages"
    private const val CALLS = "calls"
    const val SERVICE_ID = 1
    private const val CALL_ID = 2
    private const val MESSAGE_BASE = 100

    fun channels(c: Context) {
        val nm = c.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(SERVICE, "Connected", NotificationManager.IMPORTANCE_MIN).apply {
            description = "Shown while the chat is unlocked and connected"; setShowBadge(false)
        })
        nm.createNotificationChannel(NotificationChannel(MESSAGES, "Messages", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "New messages (never their text)"; lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        })
        nm.createNotificationChannel(NotificationChannel(CALLS, "Calls", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Incoming voice and video calls"; lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE),
                AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
            enableVibration(true)
        })
    }

    // Android 13+ asks for POST_NOTIFICATIONS; Android 12 has no such permission, only the app's notification switch
    private fun allowed(c: Context) = NotificationManagerCompat.from(c).areNotificationsEnabled()

    private fun openApp(c: Context, room: String? = null): PendingIntent =
        PendingIntent.getActivity(c, room?.hashCode() ?: 0, Intent(c, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            if (room != null) putExtra(MainActivity.EXTRA_ROOM, room)
        }, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    fun service(c: Context, minutes: Int): Notification =
        NotificationCompat.Builder(c, SERVICE)
            .setSmallIcon(R.drawable.ic_stat_cipherchat)
            .setContentTitle("CipherChat is unlocked")
            .setContentText("Locks $minutes min after you leave the app")
            .setOngoing(true).setSilent(true).setShowWhen(false)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(openApp(c))
            .build()

    fun message(c: Context, roomId: String, label: String, count: Int) {
        if (!allowed(c)) return
        val n = NotificationCompat.Builder(c, MESSAGES)
            .setSmallIcon(R.drawable.ic_stat_cipherchat)
            .setContentTitle(label)
            .setContentText(if (count == 1) "New encrypted message" else "$count new encrypted messages")
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(NotificationCompat.Builder(c, MESSAGES).setSmallIcon(R.drawable.ic_stat_cipherchat).setContentTitle("CipherChat").setContentText("New message").build())
            .setAutoCancel(true)
            .setContentIntent(openApp(c, roomId))
            .build()
        c.getSystemService(NotificationManager::class.java).notify(MESSAGE_BASE + (roomId.hashCode() and 0xffff), n)
    }

    fun clearMessages(c: Context, roomId: String) =
        c.getSystemService(NotificationManager::class.java).cancel(MESSAGE_BASE + (roomId.hashCode() and 0xffff))

    /**
     * Rings: Android's incoming-call notification (CallStyle, with Answer and Decline; it isn't quietened by the
     * notification cooldown) and, where the person allowed full-screen calls, the ring screen over the lock screen.
     */
    fun ringing(c: Context, inc: IncomingCall) {
        if (!allowed(c)) return
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val full = PendingIntent.getActivity(c, inc.call.hashCode(), CallActivity.ringIntent(c, inc), flags)
        val answer = PendingIntent.getActivity(c, inc.call.hashCode() + 1, CallActivity.ringIntent(c, inc, answer = true), flags)
        val decline = PendingIntent.getBroadcast(c, inc.call.hashCode() + 2,
            Intent(c, CallDeclineReceiver::class.java).putExtra(CallDeclineReceiver.EXTRA_CALL, inc.call), flags)
        val caller = Person.Builder().setName(inc.from).setImportant(true).build()
        val n = NotificationCompat.Builder(c, CALLS)
            .setSmallIcon(R.drawable.ic_stat_cipherchat)
            .setStyle(NotificationCompat.CallStyle.forIncomingCall(caller, decline, answer).setIsVideo(inc.media == "video"))
            .setContentText("End-to-end encrypted · post-quantum")
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setFullScreenIntent(full, true)
            .setContentIntent(full)
            .setGroup("calls")
            .setOngoing(true)
            .setTimeoutAfter(45_000)
            .build()
        n.flags = n.flags or Notification.FLAG_INSISTENT                       // rings until answered, declined or missed
        c.getSystemService(NotificationManager::class.java).notify(CALL_ID, n)
    }

    /** Android 14+ lets an app show a ringing call over the lock screen only once the person allowed it. */
    fun fullScreenCallsAllowed(c: Context) =
        android.os.Build.VERSION.SDK_INT < 34 || c.getSystemService(NotificationManager::class.java).canUseFullScreenIntent()

    fun openFullScreenCallSettings(c: Context) {
        if (android.os.Build.VERSION.SDK_INT < 34) return                     // allowed by default before Android 14
        c.startActivity(Intent(android.provider.Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, android.net.Uri.parse("package:" + c.packageName))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun stopRinging(c: Context) = c.getSystemService(NotificationManager::class.java).cancel(CALL_ID)

    fun clearAll(c: Context) = c.getSystemService(NotificationManager::class.java).cancelAll()
}
