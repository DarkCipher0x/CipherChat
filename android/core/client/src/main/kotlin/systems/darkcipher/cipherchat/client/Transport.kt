package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.CoroutineStart
import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.NamedGroup
import org.bouncycastle.tls.NameType
import org.bouncycastle.tls.ProtocolName
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.ServerName
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.TlsFatalAlertReceived
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Vector
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class HttpRequest(
    val method: String, val pathAndQuery: String, val headers: Map<String, String>, val body: ByteArray? = null,
    val timeoutMs: Long = 30_000,
    /** Called with (bytes sent, total) while the body uploads. */
    val progress: ((Long, Long) -> Unit)? = null,
)

class HttpResult(val status: Int, val headers: List<Pair<String, String>>, val body: ByteArray) {
    fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second
    fun all(name: String): List<String> = headers.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }
}

/** How requests reach the server. One connection per request ("Connection: close"): simple and stateless. */
interface Transport {
    val origin: URI
    suspend fun send(request: HttpRequest): HttpResult
}

class PqTlsException(message: String, cause: Throwable? = null) : IOException(message, cause)

/** Decides whether the server's certificate chain is acceptable. Returns null if it is, else the reason. */
fun interface CertificateCheck {
    fun check(host: String, chain: List<X509Certificate>): String?
}

/**
 * The platform's trusted roots (Android's system + user-approved store per the app's network security config, or the
 * JVM's on the PC): a valid chain, in date, for a server, matching the host name. Optional [pins] (base64 SHA-256 of a
 * certificate's SubjectPublicKeyInfo, as HPKP wrote them) must ALSO match one certificate in the chain.
 */
class SystemCertificateCheck(private val pins: Set<String> = emptySet()) : CertificateCheck {
    private val tm: X509TrustManager by lazy {
        val f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        f.init(null as KeyStore?)
        f.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    override fun check(host: String, chain: List<X509Certificate>): String? {
        if (chain.isEmpty()) return "no certificate"
        if (!Hostnames.matches(chain[0], host)) return "the certificate is for another name"
        try { tm.checkServerTrusted(chain.toTypedArray(), "UNKNOWN") }      // TLS 1.3: the key exchange doesn't pick the cert type
        catch (e: CertificateException) { return "the certificate isn't trusted (" + (e.message ?: "invalid chain") + ")" }
        if (pins.isNotEmpty() && chain.none { spkiPin(it) in pins }) return "the certificate doesn't match the pinned key"
        return null
    }

    companion object {
        fun spkiPin(c: X509Certificate): String = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(c.publicKey.encoded))
    }
}

/** RFC 6125 host checks: subjectAltName only (no common name), one left-most wildcard label, IP addresses exactly. */
internal object Hostnames {
    private val IPV4 = Regex("^[0-9.]+$")

    fun matches(cert: X509Certificate, host: String): Boolean {
        val names = try { cert.subjectAlternativeNames } catch (e: CertificateException) { null } ?: return false
        val h = host.lowercase().trimEnd('.')
        val ip = isIp(h)
        for (n in names) {
            val type = n[0] as? Int ?: continue
            val v = n[1] as? String ?: continue
            if (ip && type == 7 && sameIp(v, h)) return true
            if (!ip && type == 2 && dnsMatch(v.lowercase().trimEnd('.'), h)) return true
        }
        return false
    }

    fun isIp(host: String) = host.contains(':') || IPV4.matches(host)

    private fun sameIp(a: String, b: String) = try { InetAddress.getByName(a) == InetAddress.getByName(b.trim('[', ']')) } catch (e: Exception) { false }

    private fun dnsMatch(pattern: String, host: String): Boolean {
        if (!pattern.startsWith("*.")) return pattern == host
        val rest = pattern.substring(2)
        if (rest.count { it == '.' } < 1) return false                      // no "*.com"
        val dot = host.indexOf('.')
        return dot > 0 && host.substring(dot + 1) == rest
    }
}

/**
 * TLS 1.3 that only ever uses post-quantum hybrid key exchange (the Windows app's PqTls). The client offers
 * X25519MLKEM768 and nothing else (no classical group), so a server that can't do post-quantum key exchange simply
 * fails the handshake: there is no silent downgrade. After the handshake the negotiated group is checked again.
 */
object PqTls {
    val GROUPS = intArrayOf(NamedGroup.X25519MLKEM768)
    val SUITES = intArrayOf(CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256)
    private val rng = SecureRandom()

    class Connection internal constructor(private val socket: Socket, private val protocol: TlsClientProtocol) : AutoCloseable {
        val input: InputStream get() = protocol.inputStream
        val output: OutputStream get() = protocol.outputStream
        /** The negotiated key exchange group's name, for the "connection" line on screen. */
        val group: String get() = NamedGroup.getName(GROUPS[0])
        override fun close() {
            try { protocol.close() } catch (e: IOException) { }
            try { socket.close() } catch (e: IOException) { }
        }
    }

    /** Blocking: connect on [socket] and complete the handshake. */
    fun connect(socket: Socket, host: String, port: Int, check: CertificateCheck, timeoutMs: Int): Connection {
        try {
            socket.tcpNoDelay = true
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            val protocol = TlsClientProtocol(socket.getInputStream(), socket.getOutputStream())
            val client = Client(host, check)
            protocol.connect(client)
            val sp = client.ctx.securityParametersConnection
            if (sp.negotiatedGroup != NamedGroup.X25519MLKEM768 || !ProtocolVersion.TLSv13.equals(sp.negotiatedVersion)) {
                protocol.close()
                throw PqTlsException("The server didn't use post-quantum key exchange (TLS 1.3 with X25519MLKEM768).")
            }
            return Connection(socket, protocol)
        } catch (e: TlsFatalAlertReceived) {
            socket.close()
            throw PqTlsException("The server refused the post-quantum TLS handshake (" + AlertDescription.getText(e.alertDescription) + "). It needs X25519MLKEM768 support.", e)
        } catch (e: TlsFatalAlert) {
            socket.close()
            // BouncyCastle prefixes the reason with the alert ("bad_certificate(42); ..."): show only the reason
            if (e.alertDescription == AlertDescription.bad_certificate)
                throw PqTlsException("The server's certificate was refused: " + (e.message?.substringAfter("; ", "")?.ifEmpty { null } ?: "it isn't valid") + ".", e)
            if (e.alertDescription == AlertDescription.handshake_failure || e.alertDescription == AlertDescription.illegal_parameter ||
                e.alertDescription == AlertDescription.insufficient_security)
                throw PqTlsException("This server doesn't support post-quantum TLS (X25519MLKEM768), so CipherChat won't connect to it.", e)
            throw e
        } catch (e: Exception) {
            socket.close()
            throw e
        }
    }

    private class Client(private val host: String, private val check: CertificateCheck) : DefaultTlsClient(BcTlsCrypto(rng)) {
        val ctx get() = context
        override fun getSupportedVersions(): Array<ProtocolVersion> = ProtocolVersion.TLSv13.only()
        override fun getSupportedCipherSuites(): IntArray = SUITES
        override fun getSupportedGroups(namedGroupRoles: Vector<*>?): Vector<*> = Vector(GROUPS.toList())
        override fun getEarlyKeyShareGroups(): Vector<*> = Vector(GROUPS.toList())
        override fun getSNIServerNames(): Vector<*>? =
            if (Hostnames.isIp(host)) null else Vector(listOf(ServerName(NameType.host_name, host.toByteArray(Charsets.US_ASCII))))
        override fun getProtocolNames(): Vector<*> = Vector(listOf(ProtocolName.HTTP_1_1))
        override fun getAuthentication(): TlsAuthentication = Auth(host, check)
    }

    private class Auth(private val host: String, private val check: CertificateCheck) : TlsAuthentication {
        override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
            val list = serverCertificate.certificate
            if (list == null || list.isEmpty) throw TlsFatalAlert(AlertDescription.bad_certificate)
            val cf = CertificateFactory.getInstance("X.509")
            val chain = (0 until list.length).map { cf.generateCertificate(list.getCertificateAt(it).encoded.inputStream()) as X509Certificate }
            val why = check.check(host, chain)
            if (why != null) throw TlsFatalAlert(AlertDescription.bad_certificate, why)
        }
        override fun getClientCredentials(certificateRequest: org.bouncycastle.tls.CertificateRequest?): TlsCredentials? = null
    }
}

/** Runs blocking socket work so that cancelling the coroutine closes the socket (a blocked read can't see interrupts). */
internal suspend fun <T> blockingOn(socket: Socket, block: () -> T): T = coroutineScope {
    val watcher = launch(start = CoroutineStart.UNDISPATCHED) { try { awaitCancellation() } finally { try { socket.close() } catch (e: IOException) { } } }
    try { runInterruptible(Dispatchers.IO) { block() } } finally { watcher.cancel() }
}

/** The production transport: HTTPS over post-quantum-only TLS 1.3. */
class PqTlsTransport(origin: URI, private val check: CertificateCheck = SystemCertificateCheck()) : Transport {
    override val origin: URI = if (origin.scheme == "https") origin else throw IllegalArgumentException("CipherChat servers are https:// only")
    private val port = if (origin.port > 0) origin.port else 443

    override suspend fun send(request: HttpRequest): HttpResult {
        val socket = Socket()
        return blockingOn(socket) {
            PqTls.connect(socket, origin.host, port, check, request.timeoutMs.toInt()).use { c -> Http1.exchange(c.input, c.output, origin, request) }
        }
    }
}

/**
 * Plain HTTP to a server on THIS machine (127.0.0.1 / ::1 / localhost) for development and tests only, e.g. the
 * server's CIPHERCHAT_DEV mode, an SSH tunnel, or "adb reverse" from the emulator. Refuses any other host, so it can
 * never carry real traffic over a network.
 */
class LoopbackDevTransport(origin: URI) : Transport {
    override val origin: URI = origin.also {
        if (it.scheme != "http" || it.host !in setOf("127.0.0.1", "localhost", "[::1]", "::1"))
            throw IllegalArgumentException("The development transport only talks to http://127.0.0.1 or http://localhost")
    }

    override suspend fun send(request: HttpRequest): HttpResult {
        val socket = Socket()
        return blockingOn(socket) {
            socket.use { s ->
                s.tcpNoDelay = true
                s.soTimeout = request.timeoutMs.toInt()
                s.connect(InetSocketAddress(if (origin.host == "localhost") "127.0.0.1" else origin.host.trim('[', ']'), origin.port), request.timeoutMs.toInt())
                Http1.exchange(s.getInputStream(), s.getOutputStream(), origin, request)
            }
        }
    }
}

/** Just enough HTTP/1.1 for CipherChat's API: one request, one response (Content-Length, chunked or until close). */
internal object Http1 {
    private const val MAX_HEADER_BYTES = 64 * 1024
    const val MAX_BODY_BYTES = 128L * 1024 * 1024

    fun exchange(input: InputStream, output: OutputStream, origin: URI, r: HttpRequest): HttpResult {
        if (!r.pathAndQuery.startsWith("/") || r.pathAndQuery.any { it.code < 0x21 || it.code > 0x7e }) throw IllegalArgumentException("bad path")
        val head = StringBuilder()
        head.append(r.method).append(' ').append(r.pathAndQuery).append(" HTTP/1.1\r\n")
        head.append("Host: ").append(hostHeader(origin)).append("\r\n")
        head.append("Connection: close\r\n")
        for ((k, v) in r.headers) {
            if (k.isEmpty() || k.any { it <= ' ' || it == ':' || it > '~' } || v.any { it == '\r' || it == '\n' }) throw IllegalArgumentException("bad header")
            head.append(k).append(": ").append(v).append("\r\n")
        }
        if (r.body != null) head.append("Content-Length: ").append(r.body.size).append("\r\n")
        head.append("\r\n")
        output.write(head.toString().toByteArray(Charsets.US_ASCII))
        if (r.body != null) {
            val step = 64 * 1024
            var o = 0
            while (o < r.body.size) {
                val n = minOf(step, r.body.size - o)
                output.write(r.body, o, n)
                o += n
                r.progress?.invoke(o.toLong(), r.body.size.toLong())
            }
        }
        output.flush()
        return readResponse(Reader(input))
    }

    fun hostHeader(origin: URI): String {
        val default = (origin.scheme == "https" && origin.port in setOf(-1, 443)) || (origin.scheme == "http" && origin.port in setOf(-1, 80))
        return if (default) origin.host else origin.host + ":" + origin.port
    }

    fun readResponse(rd: Reader): HttpResult {
        while (true) {
            val status = rd.line()
            val parts = status.split(' ', limit = 3)
            val code = parts.getOrNull(1)?.takeIf { it.length == 3 && it.all(Char::isDigit) }?.toInt()
            if (parts.size < 2 || !parts[0].startsWith("HTTP/1.") || code == null) throw IOException("malformed HTTP response")
            val headers = ArrayList<Pair<String, String>>()
            var total = 0
            while (true) {
                val line = rd.line()
                if (line.isEmpty()) break
                total += line.length
                if (total > MAX_HEADER_BYTES) throw IOException("response headers too large")
                val i = line.indexOf(':')
                if (i <= 0) throw IOException("malformed header")
                headers.add(line.substring(0, i).trim() to line.substring(i + 1).trim())
            }
            if (code in 100..199) continue                                     // 100 Continue and friends
            val res = HttpResult(code, headers, ByteArray(0))
            val te = res.header("Transfer-Encoding")
            val cl = res.header("Content-Length")
            val body = when {
                te != null && te.contains("chunked", ignoreCase = true) -> rd.chunked(MAX_BODY_BYTES)
                cl != null -> {
                    val n = cl.takeIf { it.isNotEmpty() && it.length < 19 && it.all(Char::isDigit) }?.toLong()
                    if (n == null || n > MAX_BODY_BYTES) throw IOException("bad Content-Length")
                    rd.exact(n.toInt())
                }
                else -> rd.toEnd(MAX_BODY_BYTES)
            }
            return HttpResult(code, headers, body)
        }
    }

    class Reader(private val s: InputStream) {
        private val buf = ByteArray(16 * 1024)
        private var pos = 0
        private var len = 0

        private fun fill(): Boolean {
            pos = 0
            len = s.read(buf).coerceAtLeast(0)
            return len > 0
        }

        fun line(): String {
            val sb = StringBuilder()
            while (true) {
                if (pos >= len && !fill()) throw IOException("connection closed")
                val b = buf[pos++].toInt() and 0xff
                if (b == '\n'.code) return sb.toString().trimEnd('\r')
                if (sb.length > 8192) throw IOException("line too long")
                sb.append(b.toChar())
            }
        }

        fun exact(n: Int): ByteArray {
            val out = ByteArray(n)
            var o = 0
            while (o < n) {
                if (pos >= len && !fill()) throw IOException("connection closed early")
                val take = minOf(n - o, len - pos)
                System.arraycopy(buf, pos, out, o, take)
                pos += take; o += take
            }
            return out
        }

        fun chunked(max: Long): ByteArray {
            val ms = ByteArrayOutputStream()
            while (true) {
                val sizeLine = line().substringBefore(';').trim()
                val size = sizeLine.takeIf { it.isNotEmpty() && it.length <= 15 && it.all { c -> c.isDigit() || c.lowercaseChar() in 'a'..'f' } }?.toLong(16)
                    ?: throw IOException("bad chunk")
                if (size == 0L) {
                    while (line().isNotEmpty()) { }                            // trailers
                    return ms.toByteArray()
                }
                if (ms.size() + size > max) throw IOException("response too large")
                ms.write(exact(size.toInt()))
                line()
            }
        }

        fun toEnd(max: Long): ByteArray {
            val ms = ByteArrayOutputStream()
            ms.write(buf, pos, len - pos)
            pos = len
            while (fill()) {
                ms.write(buf, 0, len)
                if (ms.size() > max) throw IOException("response too large")
            }
            return ms.toByteArray()
        }
    }
}
