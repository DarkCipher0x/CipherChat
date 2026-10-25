using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CipherChat.Transport;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

namespace CipherChat.Transport.Tests;

/// <summary>
/// The post-quantum-only rule, proven against real TLS servers on loopback: one that offers X25519MLKEM768 (must work)
/// and one that only does classical key exchange (must be refused, never downgraded).
/// </summary>
public class PqTlsTests
{
    private sealed record TestCert(Ed25519PrivateKeyParameters Key, byte[] Der, X509Certificate2 Net);

    private static readonly TestCert Cert = MakeCert();

    private static TestCert MakeCert()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        var g = new X509V3CertificateGenerator();
        g.SetSerialNumber(BigInteger.ValueOf(Random.Shared.NextInt64(1, long.MaxValue)));
        g.SetIssuerDN(new X509Name("CN=localhost"));
        g.SetSubjectDN(new X509Name("CN=localhost"));
        g.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        g.SetNotAfter(DateTime.UtcNow.AddDays(1));
        g.SetPublicKey(kp.Public);
        g.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.DnsName, "localhost")));
        var der = g.Generate(new Asn1SignatureFactory("Ed25519", kp.Private)).GetEncoded();
        return new TestCert((Ed25519PrivateKeyParameters)kp.Private, der, new X509Certificate2(der));
    }

    /// <summary>Trusts exactly the test certificate (and checks the host name), like pinning.</summary>
    private sealed class PinnedCheck : ICertificateCheck
    {
        public string? Check(string host, X509Certificate2[] chain) =>
            host == "localhost" && chain[0].Thumbprint == Cert.Net.Thumbprint ? null : "not the test certificate";
    }

    private sealed class Server(BcTlsCrypto crypto, int[] groups) : DefaultTlsServer(crypto)
    {
        private readonly BcTlsCrypto _crypto = crypto;
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();
        public override int[] GetSupportedGroups() => groups;
        public override TlsCredentials GetCredentials()
        {
            var cert = new Certificate([], [new CertificateEntry(_crypto.CreateCertificate(Cert.Der), null)]);
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), _crypto, Cert.Key, cert, SignatureAndHashAlgorithm.ed25519);
        }
    }

    /// <summary>A one-shot HTTPS server on 127.0.0.1 offering only <paramref name="groups"/>; answers with <paramref name="response"/>.</summary>
    private static (int Port, Task<string> Request) Serve(int[] groups, string response)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var task = Task.Run(() =>
        {
            try
            {
                using var tcp = listener.AcceptTcpClient();
                tcp.ReceiveTimeout = 10000;
                var p = new TlsServerProtocol(tcp.GetStream());
                p.Accept(new Server(new BcTlsCrypto(), groups));
                var buf = new byte[8192];
                var n = p.Stream.Read(buf, 0, buf.Length);
                var req = Encoding.ASCII.GetString(buf, 0, n);
                var bytes = Encoding.ASCII.GetBytes(response);
                p.Stream.Write(bytes, 0, bytes.Length);
                p.Close();
                return req;
            }
            catch (Exception e) { return "server: " + e.GetType().Name; }
            finally { listener.Stop(); }
        });
        return (port, task);
    }

    private static HttpRequest Get(string path) => new("GET", path, new Dictionary<string, string> { ["X-Requested-With"] = "dcx-portal" }) { Timeout = TimeSpan.FromSeconds(10) };

    [Fact]
    public async Task ConnectsWithPostQuantumKeyExchange()
    {
        var (port, req) = Serve([NamedGroup.X25519MLKEM768, NamedGroup.x25519], "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}");
        var t = new PqTlsTransport(new Uri("https://localhost:" + port), new PinnedCheck());
        var r = await t.SendAsync(Get("/healthz"), CancellationToken.None);
        Assert.Equal(200, r.Status);
        Assert.Equal("{\"ok\":true}", Encoding.UTF8.GetString(r.Body));
        Assert.StartsWith("GET /healthz HTTP/1.1\r\nHost: localhost:" + port, await req);
    }

    [Fact]
    public async Task RefusesAServerWithoutPostQuantumKeyExchange()
    {
        var (port, req) = Serve([NamedGroup.x25519, NamedGroup.secp256r1], "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        var t = new PqTlsTransport(new Uri("https://localhost:" + port), new PinnedCheck());
        var e = await Assert.ThrowsAsync<PqTlsException>(() => t.SendAsync(Get("/"), CancellationToken.None));
        Assert.Contains("post-quantum", e.Message);
        Assert.StartsWith("server:", await req);                          // no request was ever sent
    }

    [Fact]
    public async Task RefusesAnUntrustedCertificate()
    {
        var (port, req) = Serve([NamedGroup.X25519MLKEM768], "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        var t = new PqTlsTransport(new Uri("https://localhost:" + port));    // the Windows store: a self-signed certificate isn't trusted
        await Assert.ThrowsAnyAsync<Exception>(() => t.SendAsync(Get("/"), CancellationToken.None));
        Assert.StartsWith("server:", await req);
    }

    [Fact]
    public async Task ReadsChunkedResponses()
    {
        var (port, _) = Serve([NamedGroup.X25519MLKEM768], "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        var t = new PqTlsTransport(new Uri("https://localhost:" + port), new PinnedCheck());
        var r = await t.SendAsync(Get("/x"), CancellationToken.None);
        Assert.Equal("hello world", Encoding.ASCII.GetString(r.Body));
        Assert.Equal(["a=1", "b=2"], r.All("Set-Cookie"));
    }

    [Fact]
    public void OnlyHttpsAndOnlyLoopbackForDevelopment()
    {
        Assert.Throws<ArgumentException>(() => new PqTlsTransport(new Uri("http://example.com")));
        Assert.Throws<ArgumentException>(() => new LoopbackDevTransport(new Uri("http://example.com:8080")));
        Assert.Throws<ArgumentException>(() => new LoopbackDevTransport(new Uri("https://localhost:8080")));
        _ = new LoopbackDevTransport(new Uri("http://127.0.0.1:8787"));
        _ = new LoopbackDevTransport(new Uri("http://localhost:8094"));
    }

    [Fact]
    public async Task LiveServerNegotiatesPostQuantumTls()
    {
        // The real deployment (skipped unless CIPHERCHAT_LIVE_ORIGIN is set, e.g. https://darkciphersystems.com)
        var origin = Environment.GetEnvironmentVariable("CIPHERCHAT_LIVE_ORIGIN");
        if (string.IsNullOrEmpty(origin)) return;
        var t = new PqTlsTransport(new Uri(origin));
        var r = await t.SendAsync(Get("/chat/api/auth/status"), CancellationToken.None);
        Assert.Equal(200, r.Status);
        Assert.Contains("\"signed_in\"", Encoding.UTF8.GetString(r.Body));
    }
}
