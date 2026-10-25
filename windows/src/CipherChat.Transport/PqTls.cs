using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CipherChat.Transport;

/// <summary>
/// TLS 1.3 that only ever uses post-quantum hybrid key exchange. The client offers X25519MLKEM768 and nothing else
/// (no classical group), so a server that can't do post-quantum key exchange simply fails the handshake: there is no
/// silent downgrade. After the handshake the negotiated group is checked again. Certificates are validated with the
/// Windows certificate store (chain, expiry, server-auth usage, host name) on top of BouncyCastle's own checks.
/// </summary>
public static class PqTls
{
    public static readonly int[] Groups = [NamedGroup.X25519MLKEM768];
    public static readonly int[] Suites = [CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256];

    /// <summary>Connects and completes the handshake; the returned stream carries the application data.</summary>
    public static async Task<PqTlsConnection> ConnectAsync(string host, int port, ICertificateCheck check, TimeSpan timeout, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true, ReceiveTimeout = (int)timeout.TotalMilliseconds, SendTimeout = (int)timeout.TotalMilliseconds };
        try
        {
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeout);
                await tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            }
            var protocol = new TlsClientProtocol(tcp.GetStream());
            var client = new Client(new BcTlsCrypto(), host, check);
            await Task.Run(() => protocol.Connect(client), ct).ConfigureAwait(false);
            var sp = client.Context!.SecurityParameters;
            if (sp.NegotiatedGroup != NamedGroup.X25519MLKEM768 || !ProtocolVersion.TLSv13.Equals(sp.NegotiatedVersion))
            {
                protocol.Close();
                throw new PqTlsException("The server didn't use post-quantum key exchange (TLS 1.3 with X25519MLKEM768).");
            }
            return new PqTlsConnection(tcp, protocol);
        }
        catch (TlsFatalAlert e) when (e.AlertDescription == AlertDescription.handshake_failure || e.AlertDescription == AlertDescription.illegal_parameter
                                       || e.AlertDescription == AlertDescription.insufficient_security)
        {
            tcp.Dispose();
            throw new PqTlsException("This server doesn't support post-quantum TLS (X25519MLKEM768), so CipherChat won't connect to it.", e);
        }
        catch (TlsFatalAlertReceived e)
        {
            tcp.Dispose();
            throw new PqTlsException("The server refused the post-quantum TLS handshake (" + AlertDescription.GetText(e.AlertDescription) + "). It needs X25519MLKEM768 support.", e);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private sealed class Client(TlsCrypto crypto, string host, ICertificateCheck check) : DefaultTlsClient(crypto)
    {
        public TlsClientContext? Context => m_context;

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();
        protected override int[] GetSupportedCipherSuites() => Suites;
        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles) => Groups.ToList();
        public override IList<int> GetEarlyKeyShareGroups() => Groups.ToList();
        protected override IList<ServerName> GetSniServerNames() => [new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(host))];
        protected override IList<ProtocolName> GetProtocolNames() => [ProtocolName.Http_1_1];
        public override TlsAuthentication GetAuthentication() => new Auth(host, check);
    }

    private sealed class Auth(string host, ICertificateCheck check) : TlsAuthentication
    {
        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            var list = serverCertificate.Certificate;
            if (list is null || list.IsEmpty) throw new TlsFatalAlert(AlertDescription.bad_certificate);
            var chain = new X509Certificate2[list.Length];
            for (var i = 0; i < list.Length; i++) chain[i] = new X509Certificate2(list.GetCertificateAt(i).GetEncoded());
            var why = check.Check(host, chain);
            if (why is not null) throw new TlsFatalAlert(AlertDescription.bad_certificate, why);
        }

        public TlsCredentials GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null!;
    }
}

public sealed class PqTlsException : Exception
{
    public PqTlsException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>A completed post-quantum TLS connection.</summary>
public sealed class PqTlsConnection(TcpClient tcp, TlsClientProtocol protocol) : IDisposable
{
    public Stream Stream => protocol.Stream;

    public void Dispose()
    {
        try { protocol.Close(); } catch (IOException) { }                  // TlsException is an IOException
        tcp.Dispose();
    }
}

/// <summary>Decides whether the server's certificate chain is acceptable. Returns null if it is, else the reason.</summary>
public interface ICertificateCheck
{
    string? Check(string host, X509Certificate2[] chain);
}

/// <summary>The Windows certificate store: a valid chain to a trusted root, in date, for server authentication, matching the host.</summary>
public sealed class SystemCertificateCheck : ICertificateCheck
{
    public string? Check(string host, X509Certificate2[] chain)
    {
        var leaf = chain[0];
        if (!leaf.MatchesHostname(host, allowWildcards: true, allowCommonName: false)) return "the certificate is for another name";
        using var x = new X509Chain();
        x.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        x.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        // like browsers: a revocation server that can't be reached doesn't block the connection; a revoked certificate does
        x.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
        x.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
        x.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
        for (var i = 1; i < chain.Length; i++) x.ChainPolicy.ExtraStore.Add(chain[i]);
        if (x.Build(leaf)) return null;
        var status = x.ChainStatus.Where(s => s.Status != X509ChainStatusFlags.NoError && s.Status != X509ChainStatusFlags.OfflineRevocation
                                              && s.Status != X509ChainStatusFlags.RevocationStatusUnknown).Select(s => s.Status.ToString()).ToArray();
        return status.Length == 0 ? null : "the certificate isn't trusted (" + string.Join(", ", status) + ")";
    }
}
