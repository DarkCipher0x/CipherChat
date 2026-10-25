package systems.darkcipher.cipherchat.client

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * Pairing codes: "cipherchat:pair/v1?server=<origin>&token=<one-time device token>" (older web chats wrote
 * "dcxchat:pair/v1?..."; both are accepted). The token is the credential for a chat-only device session, so codes are
 * shown once and never logged.
 */
object Pairing {
    private val TOKEN = Regex("^[A-Za-z0-9_-]{30,100}$")

    fun format(origin: URI, token: String): String =
        "cipherchat:pair/v1?server=" + enc(origin.scheme + "://" + Http1.hostHeader(origin)) + "&token=" + enc(token)

    class Code(val server: URI, val token: String)

    /** The server and token from a pasted or scanned code, or null if it isn't one. */
    fun parse(text: String?): Code? {
        val t = (text ?: "").trim()
        val q = when {
            t.startsWith("cipherchat:pair/v1?") -> t.substring(19)
            t.startsWith("dcxchat:pair/v1?") -> t.substring(16)
            else -> return null
        }
        var server: String? = null
        var token: String? = null
        for (part in q.split('&')) {
            val i = part.indexOf('=')
            if (i <= 0) continue
            val v = try { URLDecoder.decode(part.substring(i + 1), "UTF-8") } catch (e: IllegalArgumentException) { return null }
            when (part.substring(0, i)) { "server" -> server = v; "token" -> token = v }
        }
        if (server == null || token == null || !TOKEN.matches(token)) return null
        val uri = try { URI(server) } catch (e: Exception) { return null }
        val host = uri.host ?: return null
        val local = host == "127.0.0.1" || host == "localhost" || host == "[::1]"
        if (!(uri.scheme == "https" || (uri.scheme == "http" && local))) return null
        if ((uri.rawPath ?: "") !in setOf("", "/") || uri.rawQuery != null || uri.rawUserInfo != null || uri.rawFragment != null) return null
        return Code(URI(uri.scheme + "://" + host + (if (uri.port > 0) ":" + uri.port else "") + "/"), token)
    }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
}
