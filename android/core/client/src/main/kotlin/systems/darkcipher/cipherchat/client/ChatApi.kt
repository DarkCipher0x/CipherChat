package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.strOrNull
import java.io.IOException
import java.net.URI
import kotlin.math.ceil

/** A refused request: the server's message plus its flags (reauth, denied, stale, rotate...). status 0 = offline. */
class ApiException(val status: Int, val body: JsonObject, message: String) : Exception(message) {
    fun flag(name: String) = body.flag(name)
    val denied get() = flag("denied")
    val offline get() = status == 0
}

/** The person cancelled a prompt (authenticator code, passkey): nothing was changed. */
class Cancelled(message: String = "Cancelled: nothing was changed.") : Exception(message)

internal fun JsonObject.flag(k: String) = (this[k] as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull == true

/** Asks the person for their current authenticator code (shows [error] after a wrong one); null = cancelled. */
typealias AskCode = suspend (error: String?) -> String?

/**
 * Gets a passkey assertion for the server's WebAuthn request options (publicKey) as the browser's PublicKeyCredential
 * JSON (Android's Credential Manager returns exactly this). [origin] is this server's origin. Null = cancelled or none.
 */
typealias SignPasskey = suspend (publicKey: JsonObject, origin: String) -> JsonObject?

/**
 * The CipherChat server API (the Windows app's ChatApi). One session cookie (whatever the server sets), sent only to
 * this server's origin. Every write carries the CSRF headers the server requires. When the session is gone and
 * [resume] is set (a paired device's token), it signs in again once and retries.
 */
class ChatApi(private val transport: Transport, private val userAgent: String) {
    private val lock = Any()
    private var cookie: String? = null                                      // "name=value"

    val origin: URI get() = transport.origin
    val originText: String get() = origin.scheme + "://" + Http1.hostHeader(origin)
    var ask: AskCode? = null
    /** When set, "confirm it's you" tries a passkey first and falls back to the authenticator code. */
    var passkey: SignPasskey? = null
    /** Re-establishes a session (e.g. device sign-in); true if it worked. */
    var resume: (suspend () -> Boolean)? = null
    val hasSession: Boolean get() = synchronized(lock) { cookie != null }

    // ---------------------------------------------------------------- plumbing
    private fun headers(contentType: String?): Map<String, String> {
        val h = linkedMapOf(
            "X-Requested-With" to "dcx-portal", "Origin" to originText, "User-Agent" to userAgent,
            "Accept" to "application/json", "Cache-Control" to "no-store",
        )
        if (contentType != null) h["Content-Type"] = contentType
        synchronized(lock) { cookie?.let { h["Cookie"] = it } }
        return h
    }

    private fun takeCookies(r: HttpResult) {
        for (sc in r.all("Set-Cookie")) {
            val first = sc.substringBefore(';').trim()
            val eq = first.indexOf('=')
            if (eq <= 0) continue
            val expired = sc.contains("Max-Age=0", ignoreCase = true) || eq == first.length - 1
            synchronized(lock) { cookie = if (expired) null else first }
        }
    }

    private class Raw(val status: Int, val data: JsonObject, val res: HttpResult)

    private suspend fun raw(method: String, path: String, body: ByteArray?, contentType: String?, timeoutMs: Long = NORMAL,
                            progress: ((Long, Long) -> Unit)? = null): Raw {
        val r = try {
            transport.send(HttpRequest(method, path, headers(contentType), body, timeoutMs, progress))
        } catch (e: CancellationException) { throw e }
        catch (e: PqTlsException) { throw ApiException(0, JsonObject(emptyMap()), e.message ?: "TLS failed") }
        catch (e: IOException) { throw ApiException(0, JsonObject(emptyMap()), "Couldn't reach the server. Check your connection and try again.") }
        takeCookies(r)
        var data = JsonObject(emptyMap())
        if ((r.header("Content-Type") ?: "").startsWith("application/json", ignoreCase = true) && r.body.isNotEmpty()) {
            data = try { Json.parseToJsonElement(String(r.body, Charsets.UTF_8)) as? JsonObject ?: data } catch (e: Exception) { data }
        }
        return Raw(r.status, data, r)
    }

    private fun fail(status: Int, data: JsonObject) =
        ApiException(status, data, data.strOrNull("error") ?: "The server refused that (HTTP $status).")

    private fun json(o: JsonObject) = o.toString().toByteArray(Charsets.UTF_8)

    /** GET (body null) or POST to /chat/api/<path>, with the reauth and resume retries. */
    suspend fun call(path: String, body: JsonObject? = null, ask: AskCode? = null, timeoutMs: Long = NORMAL): JsonObject {
        val bytes = body?.let(::json)
        val full = "/chat/api/$path"
        var attempt = 0
        while (true) {
            val r = raw(if (body == null) "GET" else "POST", full, bytes, if (body == null) null else "application/json", timeoutMs)
            if (r.status in 200..299) return r.data
            if (r.status == 401 && r.data.flag("reauth") && attempt < 2) {
                val pk = passkey
                if (attempt == 0 && pk != null && passkeyReauth(pk)) { attempt++; continue }
                reauth(ask ?: this.ask ?: throw fail(r.status, r.data))
                attempt++
                continue
            }
            val res = resume
            if (r.status == 403 && !r.data.flag("denied") && attempt == 0 && res != null && res()) { attempt++; continue }
            throw fail(r.status, r.data)
        }
    }

    // ---------------------------------------------------------------- sign-in
    suspend fun status(): JsonObject = raw("GET", "/chat/api/auth/status", null, null).data

    suspend fun login(username: String, password: String, code: String): String {
        val r = raw("POST", "/chat/api/auth/login", json(buildJsonObject { put("username", username); put("password", password); put("code", code) }), "application/json")
        if (r.status != 200) throw fail(r.status, r.data)
        return r.data.strOrNull("user") ?: username
    }

    /** A paired device's token for a chat-only session. Returns (user, device id). */
    suspend fun deviceSignIn(token: String): Pair<String, String> {
        val r = raw("POST", "/chat/api/auth/device", json(buildJsonObject { put("token", token) }), "application/json")
        if (r.status != 200) throw fail(r.status, r.data)
        return (r.data.strOrNull("user") ?: throw fail(r.status, r.data)) to (r.data.strOrNull("device") ?: "")
    }

    suspend fun logout() {
        try { raw("POST", "/chat/api/auth/logout", "{}".toByteArray(), "application/json") }
        finally { synchronized(lock) { cookie = null } }
    }

    /** A fresh authenticator code for the next few minutes of sensitive actions. */
    suspend fun reauth(ask: AskCode) {
        var err: String? = null
        repeat(5) {
            val code = ask(err) ?: throw Cancelled()
            val r = raw("POST", "/chat/api/auth/reauth", json(buildJsonObject { put("code", code) }), "application/json")
            if (r.status == 200) return
            err = r.data.strOrNull("error") ?: "That code isn't valid."
        }
        throw ApiException(401, JsonObject(emptyMap()), "Too many wrong codes. Wait a moment and try again.")
    }

    // ---------------------------------------------------------------- passkeys (passkeys.py on the server)
    private suspend fun passkeyCeremony(purpose: String, sign: SignPasskey): Raw {
        val begin = raw("POST", "/chat/api/auth/passkey/begin", json(buildJsonObject { put("purpose", purpose) }), "application/json")
        if (begin.status != 200) throw fail(begin.status, begin.data)
        val pk = begin.data["publicKey"] as? JsonObject ?: throw fail(begin.status, begin.data)
        val cred = sign(pk, originText) ?: throw Cancelled("Cancelled.")
        val finish = buildJsonObject { put("purpose", purpose); put("flow", begin.data["flow"] ?: JsonPrimitive("")); put("credential", cred) }
        return raw("POST", "/chat/api/auth/passkey/finish", json(finish), "application/json")
    }

    /** Signs in with a passkey (the phone's, or a password manager such as Bitwarden). Returns the user. */
    suspend fun passkeyLogin(sign: SignPasskey): String {
        val r = passkeyCeremony("login", sign)
        if (r.status != 200) throw fail(r.status, r.data)
        return r.data.strOrNull("user") ?: throw fail(r.status, r.data)
    }

    /** "Confirm it's you" with a passkey. False when there's none to use (not added, cancelled, not offered here). */
    suspend fun passkeyReauth(sign: SignPasskey): Boolean =
        try { passkeyCeremony("reauth", sign).status == 200 }
        catch (e: ApiException) { if (e.offline) throw e; false }
        catch (e: Cancelled) { false }

    // ---------------------------------------------------------------- attachments and polling
    /** Uploads sealed ciphertext; returns {id, size, sha3} as the server computed them. */
    suspend fun upload(roomId: String, sealed: ByteArray, progress: ((Long, Long) -> Unit)?): JsonObject {
        val timeout = 30_000L + ceil(sealed.size / 262144.0).toLong() * 1000
        var attempt = 0
        while (true) {
            val r = raw("POST", "/chat/api/upload/$roomId", sealed, "application/octet-stream", timeout, progress)
            if (r.status == 200) return r.data
            val res = resume
            if (r.status == 403 && !r.data.flag("denied") && attempt == 0 && res != null && res()) { attempt++; continue }
            throw fail(r.status, r.data)
        }
    }

    suspend fun download(roomId: String, blobId: String, size: Long): ByteArray {
        val r = raw("GET", "/chat/api/blob/$roomId/$blobId", null, null, 30_000L + ceil(size / 262144.0).toLong() * 1000)
        if (r.status == 200) return r.res.body
        throw if (r.status == 404) ApiException(404, r.data, "That attachment isn't on the server any more.") else fail(r.status, r.data)
    }

    /**
     * The server holds a poll for up to 25 s; 45 s without an answer means the connection is dead. sig = the last call
     * signal seen (calls.py): newer signals come back in "signals".
     */
    suspend fun poll(since: Long, rev: Long, sig: Long): JsonObject = call("poll?since=$since&rev=$rev&sig=$sig", timeoutMs = 45_000)

    companion object { const val NORMAL = 30_000L }
}
