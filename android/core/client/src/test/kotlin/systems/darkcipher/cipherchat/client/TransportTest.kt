package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.CertificateEntry
import org.bouncycastle.tls.DefaultTlsServer
import org.bouncycastle.tls.HashAlgorithm
import org.bouncycastle.tls.NamedGroup
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAlgorithm
import org.bouncycastle.tls.SignatureAndHashAlgorithm
import org.bouncycastle.tls.TlsCredentialedSigner
import org.bouncycastle.tls.TlsServerProtocol
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import kotlin.concurrent.thread

/**
 * The phone's transport: HTTP/1.1 framing, pairing codes, and post-quantum-only TLS against real servers on this
 * machine (127.0.0.1 only): a BouncyCastle server that does X25519MLKEM768, and the JDK's own TLS 1.3 server, which
 * can't (so the phone must refuse it rather than fall back).
 */
class TransportTest {
    private fun http(text: String) = Http1.readResponse(Http1.Reader(ByteArrayInputStream(text.toByteArray(Charsets.ISO_8859_1))))

    @Test fun parsesContentLengthChunkedAndInterimResponses() {
        val a = http("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
        assertEquals(200, a.status); assertEquals("{}", String(a.body))
        val b = http("HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nT: 1\r\n\r\n")
        assertEquals("abcde", String(b.body)); assertEquals(listOf("a=1", "b=2"), b.all("Set-Cookie"))
        assertEquals("until close", String(http("HTTP/1.0 200 OK\r\n\r\nuntil close").body))
    }

    @Test fun refusesMalformedResponses() {
        for (bad in listOf("HTTP/1.1 2000 OK\r\n\r\n", "SPDY 200\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
                           "HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n", "HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
                           "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"))
            assertThrows(bad, IOException::class.java) { http(bad) }
    }

    @Test fun refusesHeaderInjection() {
        val r = HttpRequest("GET", "/x", mapOf("X-A" to "1\r\nX-Evil: 2"))
        assertThrows(IllegalArgumentException::class.java) { Http1.exchange(ByteArrayInputStream(ByteArray(0)), java.io.ByteArrayOutputStream(), URI("http://127.0.0.1:1"), r) }
        assertThrows(IllegalArgumentException::class.java) {
            Http1.exchange(ByteArrayInputStream(ByteArray(0)), java.io.ByteArrayOutputStream(), URI("http://127.0.0.1:1"), HttpRequest("GET", "/a b", emptyMap()))
        }
    }

    @Test fun pairingCodesRoundTripAndRefuseOthers() {
        val token = "A".repeat(43)
        val c = Pairing.parse(Pairing.format(URI("https://chat.example.net"), token))!!
        assertEquals("https://chat.example.net/", c.server.toString()); assertEquals(token, c.token)
        assertEquals("http://127.0.0.1:8094/", Pairing.parse("dcxchat:pair/v1?server=http%3A%2F%2F127.0.0.1%3A8094&token=$token")!!.server.toString())
        for (bad in listOf("cipherchat:pair/v1?server=http%3A%2F%2Fevil.example&token=$token",             // plain http off this machine
                           "cipherchat:pair/v1?server=https%3A%2F%2Fa.example%2Fpath&token=$token",
                           "cipherchat:pair/v1?server=https%3A%2F%2Fu%40a.example&token=$token",
                           "cipherchat:pair/v1?server=https%3A%2F%2Fa.example&token=short", "https://a.example", ""))
            assertNull(bad, Pairing.parse(bad))
    }

    @Test fun refusesNonLoopbackDevTransportAndPlainHttps() {
        assertThrows(IllegalArgumentException::class.java) { LoopbackDevTransport(URI("http://192.168.1.10:8094")) }
        assertThrows(IllegalArgumentException::class.java) { PqTlsTransport(URI("http://chat.example.net")) }
    }

    // ------------------------------------------------------------------------------------------- real TLS on 127.0.0.1
    private val trustTestCert = CertificateCheck { host, chain ->
        if (chain[0] == cert && Hostnames.matches(chain[0], host)) null else "not the test certificate"
    }

    private fun get(origin: URI, check: CertificateCheck): HttpResult = runBlocking {
        PqTlsTransport(origin, check).send(HttpRequest("GET", "/chat/api/auth/status", mapOf("Accept" to "application/json"), timeoutMs = 10_000))
    }

    @Test fun completesPostQuantumTlsWithAServerThatOffersIt() {
        val port = bcServer(intArrayOf(NamedGroup.X25519MLKEM768, NamedGroup.x25519))
        val r = get(URI("https://127.0.0.1:$port"), trustTestCert)
        assertEquals(200, r.status); assertEquals("""{"pq":true}""", String(r.body))
        assertEquals(NamedGroup.X25519MLKEM768, lastGroup)
    }

    @Test fun refusesAServerWithoutPostQuantumKeyExchange() {
        val bc = bcServer(intArrayOf(NamedGroup.x25519, NamedGroup.secp256r1))
        val e1 = assertThrows(PqTlsException::class.java) { get(URI("https://127.0.0.1:$bc"), trustTestCert) }
        assertTrue(e1.message, e1.message!!.contains("X25519MLKEM768"))
        val jdk = jdkServer()
        val e2 = assertThrows(PqTlsException::class.java) { get(URI("https://127.0.0.1:$jdk"), trustTestCert) }
        assertTrue(e2.message, e2.message!!.contains("X25519MLKEM768"))
    }

    @Test fun refusesUntrustedOrWrongNameCertificates() {
        val port = bcServer(intArrayOf(NamedGroup.X25519MLKEM768))
        val e = assertThrows(PqTlsException::class.java) { get(URI("https://127.0.0.1:$port"), SystemCertificateCheck()) }
        assertTrue(e.message, e.message!!.contains("isn't trusted"))
        val pinned = SystemCertificateCheck(setOf(SystemCertificateCheck.spkiPin(cert)))
        assertThrows(PqTlsException::class.java) { get(URI("https://127.0.0.1:$port"), pinned) }       // a pin never replaces the chain check
        assertTrue(Hostnames.matches(cert, "localhost") && Hostnames.matches(cert, "127.0.0.1"))
        assertTrue(!Hostnames.matches(cert, "evil.localhost") && !Hostnames.matches(cert, "127.0.0.2"))
    }

    @Test fun postQuantumTlsToTheInternet() {
        // Cloudflare's edge does X25519MLKEM768; skipped when this PC is offline
        val reachable = try { Socket().use { it.connect(InetSocketAddress("cloudflare.com", 443), 3000) }; true } catch (e: IOException) { false }
        assumeTrue(reachable)
        val r = runBlocking { PqTlsTransport(URI("https://cloudflare.com")).send(HttpRequest("GET", "/cdn-cgi/trace", emptyMap(), timeoutMs = 10_000)) }
        assertEquals(200, r.status)
        assertTrue(String(r.body).contains("tls=TLSv1.3"))
    }

    companion object {
        private lateinit var dir: File
        private lateinit var key: PrivateKey
        private lateinit var cert: X509Certificate
        private lateinit var store: KeyStore
        private val servers = ArrayList<ServerSocket>()
        @Volatile private var lastGroup = -1
        private val pass = "test-only".toCharArray()

        /** A throwaway P-256 certificate for localhost / 127.0.0.1 made with the JDK's keytool (no network, nothing installed). */
        @BeforeClass @JvmStatic fun makeCertificate() {
            dir = kotlin.io.path.createTempDirectory("cc-tls").toFile()
            val ks = File(dir, "s.p12")
            val keytool = File(System.getProperty("java.home"), "bin/keytool" + if (File.separatorChar == '\\') ".exe" else "")
            val p = ProcessBuilder(keytool.path, "-genkeypair", "-alias", "s", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
                "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2", "-keystore", ks.path, "-storetype", "PKCS12",
                "-storepass", String(pass), "-keypass", String(pass)).redirectErrorStream(true).start()
            val out = p.inputStream.readBytes()
            check(p.waitFor() == 0) { String(out) }
            store = KeyStore.getInstance("PKCS12").apply { ks.inputStream().use { load(it, pass) } }
            key = store.getKey("s", pass) as PrivateKey
            cert = store.getCertificate("s") as X509Certificate
        }

        @AfterClass @JvmStatic fun stop() {
            for (s in servers) s.close()
            dir.deleteRecursively()
        }

        private fun listen(): ServerSocket = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1")).also { servers.add(it) }

        private fun answer(input: java.io.InputStream, output: java.io.OutputStream) {
            val rd = Http1.Reader(input)
            while (rd.line().isNotEmpty()) { }
            output.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"pq\":true}".toByteArray())
            output.flush()
        }

        /** A BouncyCastle TLS 1.3 server offering [groups]. */
        private fun bcServer(groups: IntArray): Int {
            val ss = listen()
            thread(isDaemon = true) {
                while (!ss.isClosed) {
                    val s = try { ss.accept() } catch (e: IOException) { break }
                    thread(isDaemon = true) {
                        s.use {
                            try {
                                val crypto = BcTlsCrypto(SecureRandom())
                                val proto = TlsServerProtocol(s.getInputStream(), s.getOutputStream())
                                val server = object : DefaultTlsServer(crypto) {
                                    override fun getSupportedVersions(): Array<ProtocolVersion> = ProtocolVersion.TLSv13.only()
                                    override fun getSupportedGroups(): IntArray = groups
                                    override fun getCredentials(): TlsCredentialedSigner {
                                        val chain = Certificate(ByteArray(0), arrayOf(CertificateEntry(crypto.createCertificate(cert.encoded), null)))
                                        return BcDefaultTlsCredentialedSigner(TlsCryptoParameters(context), crypto, PrivateKeyFactory.createKey(key.encoded), chain,
                                            SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa))
                                    }
                                    override fun notifyHandshakeComplete() { super.notifyHandshakeComplete(); lastGroup = context.securityParametersConnection.negotiatedGroup }
                                }
                                proto.accept(server)
                                answer(proto.inputStream, proto.outputStream)
                                proto.close()
                            } catch (e: Exception) { System.err.println("test TLS server: " + e); e.printStackTrace() }
                        }
                    }
                }
            }
            return ss.localPort
        }

        /** The JDK's own TLS 1.3 server (no post-quantum groups in Java 21). */
        private fun jdkServer(): Int {
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, pass) }
            val ctx = SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
            val ss = ctx.serverSocketFactory.createServerSocket(0, 10, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
            servers.add(ss)
            thread(isDaemon = true) {
                while (!ss.isClosed) {
                    val s = try { ss.accept() } catch (e: IOException) { break }
                    thread(isDaemon = true) { s.use { try { answer(it.getInputStream(), it.getOutputStream()) } catch (e: IOException) { } } }
                }
            }
            return ss.localPort
        }
    }
}
