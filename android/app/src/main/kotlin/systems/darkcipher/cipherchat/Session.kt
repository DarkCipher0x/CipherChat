package systems.darkcipher.cipherchat

import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.str
import kotlinx.serialization.json.JsonObject
import systems.darkcipher.cipherchat.client.ApiException
import systems.darkcipher.cipherchat.client.AskCode
import systems.darkcipher.cipherchat.client.ChatApi
import systems.darkcipher.cipherchat.client.ChatEngine
import systems.darkcipher.cipherchat.client.LoopbackDevTransport
import systems.darkcipher.cipherchat.client.Me
import systems.darkcipher.cipherchat.client.Pairing
import systems.darkcipher.cipherchat.client.PqTlsTransport
import systems.darkcipher.cipherchat.client.Transport
import systems.darkcipher.cipherchat.call.CallBridge
import systems.darkcipher.cipherchat.security.Vault
import java.io.File
import java.net.URI

/** A server this phone is paired with. The device token signs the phone in (chat only) without a password. */
data class SavedServer(val origin: String, val user: String, val deviceId: String, val deviceToken: String, val name: String) {
    fun toJson() = buildJsonObject { put("origin", origin); put("user", user); put("device_id", deviceId); put("device_token", deviceToken); put("name", name) }
    companion object {
        fun from(o: JsonObject) = SavedServer(o.str("origin"), o.str("user"), o.str("device_id"), o.str("device_token"), o.str("name"))
    }
}

data class Saved(val servers: List<SavedServer> = emptyList(), val autoLockMinutes: Int = 15,
                 /** Messages still waiting to send when the chat locked, per "origin|user" (ChatEngine.outboxSnapshot). */
                 val outbox: Map<String, List<JsonObject>> = emptyMap()) {
    fun toJson() = buildJsonObject {
        put("v", 1); put("servers", buildJsonArray { servers.forEach { add(it.toJson()) } }); put("auto_lock_minutes", autoLockMinutes)
        put("outbox", buildJsonObject { outbox.forEach { (k, v) -> put(k, JsonArray(v)) } })
    }
    companion object {
        fun from(o: JsonObject) = Saved((o["servers"] as? JsonArray)?.map { SavedServer.from(it as JsonObject) } ?: emptyList(),
            (o["auto_lock_minutes"] as? JsonPrimitive)?.intOrNull ?: 15,
            (o["outbox"] as? JsonObject)?.mapValues { (_, v) -> (v as? JsonArray)?.filterIsInstance<JsonObject>() ?: emptyList() } ?: emptyMap())
    }
}

/**
 * Everything the app needs (the Windows app's Session): which server, how this phone signs in to it (a paired device
 * token, a passkey, or password + code), the unlocked identity and the running chat. Keys live here only between
 * unlock and [lock].
 */
class Session(filesDir: File, private val devBuild: Boolean) {
    val vault = Vault(filesDir)

    enum class Stage { VaultLocked, Connect, Gate, Chat }

    private val _stage = MutableStateFlow(Stage.VaultLocked)
    val stage: StateFlow<Stage> = _stage.asStateFlow()
    var saved = Saved(); private set
    var api: ChatApi? = null; private set
    var state: JsonObject? = null; private set
    var engine: ChatEngine? = null; private set
    var server: SavedServer? = null; private set
    /** Set by the activity: shows the phone's passkey sheet. */
    var passkeys: Passkeys? = null

    // ------------------------------------------------------------------------------------------- the vault
    suspend fun unlockVault(activity: FragmentActivity) {
        val bytes = vault.unlock(activity)
        saved = if (bytes.isEmpty()) Saved() else Saved.from(Json.parseToJsonElement(String(bytes, Charsets.UTF_8)) as JsonObject)
        bytes.fill(0)
        _stage.value = Stage.Connect
    }

    private fun persist() = vault.save(saved.toJson().toString().toByteArray(Charsets.UTF_8))

    fun setAutoLock(minutes: Int) { saved = saved.copy(autoLockMinutes = minutes); persist() }

    // ------------------------------------------------------------------------------------------- signing in
    /** Release builds talk only https:// over PQ TLS; debug builds also reach a server on this phone (adb reverse). */
    private fun transportFor(origin: URI): Transport =
        if (origin.scheme == "http" && devBuild) LoopbackDevTransport(origin) else PqTlsTransport(origin)

    private fun checkOrigin(origin: URI) {
        if (origin.scheme != "https" && !(devBuild && origin.scheme == "http")) throw IllegalArgumentException("CipherChat servers are https:// only.")
    }

    private fun newApi(origin: URI): ChatApi {
        val a = ChatApi(transportFor(origin), USER_AGENT)
        // a paired phone signs itself back in when its session ends (sessions idle out; the device token lasts much longer)
        a.resume = {
            val s = server
            if (s == null) false else try { a.deviceSignIn(s.deviceToken); true } catch (e: ApiException) { false }
        }
        a.passkey = { pk, origin -> passkeys?.sign(pk, origin) }
        return a
    }

    suspend fun resume(s: SavedServer) {
        server = s
        api = newApi(URI(s.origin)).also { it.deviceSignIn(s.deviceToken) }
        state = api!!.call("state")
        _stage.value = Stage.Gate
    }

    /** A pairing code (typed, pasted or scanned): sign in with it and remember this phone. */
    suspend fun pair(code: String) {
        val p = Pairing.parse(code) ?: throw IllegalArgumentException("That isn't a CipherChat pairing code. In the web chat type /pair, or open Devices in the Windows app, to make one.")
        if (p.server.scheme == "http" && !devBuild) throw IllegalArgumentException("That code is for a development server. CipherChat only connects to https:// servers.")
        val a = newApi(p.server)
        val (user, device) = a.deviceSignIn(p.token)
        val origin = p.server.toString().trimEnd('/')
        val s = SavedServer(origin, user, device, p.token, p.server.host)
        saved = saved.copy(servers = listOf(s) + saved.servers.filter { !(it.origin == origin && it.user == user) })
        persist()
        server = s
        api = a
        state = a.call("state")
        _stage.value = Stage.Gate
    }

    /** Password + authenticator code (nothing is remembered on this phone). */
    suspend fun signIn(origin: URI, user: String, password: String, code: String) {
        checkOrigin(origin)
        server = null
        val a = newApi(origin)
        a.login(user, password, code)
        api = a
        state = a.call("state")
        _stage.value = Stage.Gate
    }

    /** A passkey: nothing is remembered on this phone. */
    suspend fun passkeySignIn(origin: URI) {
        checkOrigin(origin)
        server = null
        val a = newApi(origin)
        val pk = passkeys ?: throw IllegalStateException("Passkeys aren't available on this phone.")
        a.passkeyLogin { o, org -> pk.sign(o, org) }
        api = a
        state = a.call("state")
        _stage.value = Stage.Gate
    }

    suspend fun refreshState() { state = api!!.call("state") }

    fun forget(s: SavedServer) {
        saved = saved.copy(servers = saved.servers.filter { it != s })
        persist()
    }

    // ------------------------------------------------------------------------------------------- the chat
    suspend fun start(me: Me, ask: AskCode) {
        val a = api!!
        a.ask = ask
        val e = ChatEngine(a, me)
        engine = e
        e.start()
        CallBridge.engine = e
        // messages that were still waiting when the chat last locked go back in the queue
        val key = a.originText + "|" + me.user
        saved.outbox[key]?.let { waiting ->
            e.restoreOutbox(waiting)
            saved = saved.copy(outbox = saved.outbox - key)
            if (vault.open) persist()
        }
        _stage.value = Stage.Chat
    }

    /** Keeps messages that haven't reached the server yet in the vault (sealed by the phone's hardware key), so locking
     *  doesn't lose them; they're sent after the next unlock. */
    private fun keepOutbox() {
        val e = engine ?: return
        val waiting = e.outboxSnapshot()
        if (waiting.isEmpty() || !vault.open) return
        saved = saved.copy(outbox = saved.outbox + ((e.api.originText + "|" + e.myUser) to waiting))
        try { persist() } catch (x: Exception) { }
    }

    /** Wipes the chat keys from memory; the phone stays signed in and paired. */
    fun lockChat() {
        CallBridge.engine = null
        keepOutbox()
        engine?.lock()
        engine = null
        if (_stage.value == Stage.Chat) _stage.value = Stage.Gate
    }

    /** Locks everything: the chat keys and the vault's data key. The next open needs the fingerprint again. */
    fun lockAll() {
        CallBridge.engine = null
        keepOutbox()
        engine?.lock()
        engine = null
        vault.lock()
        api = null; state = null; server = null
        _stage.value = Stage.VaultLocked
    }

    suspend fun signOut(forgetPhone: Boolean) {
        CallBridge.engine = null
        engine?.lock()
        engine = null
        api?.let { try { it.logout() } catch (e: ApiException) { } }
        val s = server
        if (forgetPhone && s != null) forget(s)
        api = null; state = null; server = null
        _stage.value = Stage.Connect
    }

    companion object { const val USER_AGENT = "CipherChat/" + BuildConfig.VERSION_NAME + " (Android)" }
}
