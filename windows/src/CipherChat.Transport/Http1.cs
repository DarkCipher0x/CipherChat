using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace CipherChat.Transport;

public sealed record HttpRequest(string Method, string PathAndQuery, IReadOnlyDictionary<string, string> Headers, byte[]? Body = null)
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Called with (bytes sent, total) while the body uploads.</summary>
    public Action<long, long>? Progress { get; init; }
}

public sealed record HttpResult(int Status, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body)
{
    public string? Header(string name) => Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
    public IEnumerable<string> All(string name) => Headers.Where(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value);
}

/// <summary>How requests reach the server. One connection per request ("Connection: close"): simple and stateless.</summary>
public interface ITransport
{
    Uri Origin { get; }
    Task<HttpResult> SendAsync(HttpRequest request, CancellationToken ct);
}

/// <summary>The production transport: HTTPS over post-quantum-only TLS 1.3.</summary>
public sealed class PqTlsTransport(Uri origin, ICertificateCheck? check = null) : ITransport
{
    private readonly ICertificateCheck _check = check ?? new SystemCertificateCheck();

    public Uri Origin { get; } = origin.Scheme == Uri.UriSchemeHttps ? origin : throw new ArgumentException("CipherChat servers are https:// only");

    public async Task<HttpResult> SendAsync(HttpRequest request, CancellationToken ct)
    {
        using var conn = await PqTls.ConnectAsync(Origin.Host, Origin.Port, _check, request.Timeout, ct).ConfigureAwait(false);
        return await Http1.ExchangeAsync(conn.Stream, Origin, request, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// Plain HTTP to a server on THIS machine (127.0.0.1 / ::1 / localhost) for development and tests only, e.g. the
/// server's CIPHERCHAT_DEV mode or an SSH tunnel to one. Refuses any other host, so it can never carry real traffic
/// over a network.
/// </summary>
public sealed class LoopbackDevTransport : ITransport
{
    public LoopbackDevTransport(Uri origin)
    {
        if (origin.Scheme != Uri.UriSchemeHttp || !(origin.IsLoopback || origin.Host == "localhost"))
            throw new ArgumentException("The development transport only talks to http://127.0.0.1 or http://localhost");
        Origin = origin;
    }

    public Uri Origin { get; }

    public async Task<HttpResult> SendAsync(HttpRequest request, CancellationToken ct)
    {
        using var tcp = new TcpClient { NoDelay = true, ReceiveTimeout = (int)request.Timeout.TotalMilliseconds, SendTimeout = (int)request.Timeout.TotalMilliseconds };
        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            cts.CancelAfter(request.Timeout);
            await tcp.ConnectAsync(Origin.Host == "localhost" ? "127.0.0.1" : Origin.Host, Origin.Port, cts.Token).ConfigureAwait(false);
        }
        return await Http1.ExchangeAsync(tcp.GetStream(), Origin, request, ct).ConfigureAwait(false);
    }
}

/// <summary>Just enough HTTP/1.1 for CipherChat's API: one request, one response (Content-Length, chunked or until close).</summary>
internal static class Http1
{
    private const int MaxHeaderBytes = 64 * 1024;
    private const long MaxBodyBytes = 128L * 1024 * 1024;

    public static async Task<HttpResult> ExchangeAsync(Stream s, Uri origin, HttpRequest r, CancellationToken ct)
    {
        if (!r.PathAndQuery.StartsWith('/') || r.PathAndQuery.Any(ch => ch < 0x21 || ch > 0x7e)) throw new ArgumentException("bad path");
        var head = new StringBuilder();
        head.Append(r.Method).Append(' ').Append(r.PathAndQuery).Append(" HTTP/1.1\r\n");
        head.Append("Host: ").Append(origin.IsDefaultPort ? origin.Host : origin.Host + ":" + origin.Port).Append("\r\n");
        head.Append("Connection: close\r\n");
        foreach (var (k, v) in r.Headers)
        {
            if (k.Any(ch => ch <= ' ' || ch == ':' || ch > '~') || v.Any(ch => ch == '\r' || ch == '\n')) throw new ArgumentException("bad header");
            head.Append(k).Append(": ").Append(v).Append("\r\n");
        }
        if (r.Body is not null) head.Append("Content-Length: ").Append(r.Body.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
        head.Append("\r\n");
        var hb = Encoding.ASCII.GetBytes(head.ToString());
        await s.WriteAsync(hb, ct).ConfigureAwait(false);
        if (r.Body is not null)
        {
            const int step = 64 * 1024;
            for (var o = 0; o < r.Body.Length; o += step)
            {
                await s.WriteAsync(r.Body.AsMemory(o, Math.Min(step, r.Body.Length - o)), ct).ConfigureAwait(false);
                r.Progress?.Invoke(Math.Min(o + step, r.Body.Length), r.Body.Length);
            }
        }
        await s.FlushAsync(ct).ConfigureAwait(false);
        return await ReadResponseAsync(new Reader(s), ct).ConfigureAwait(false);
    }

    private static async Task<HttpResult> ReadResponseAsync(Reader rd, CancellationToken ct)
    {
        while (true)
        {
            var status = await rd.LineAsync(ct).ConfigureAwait(false);
            var parts = status.Split(' ', 3);
            if (parts.Length < 2 || !parts[0].StartsWith("HTTP/1.", StringComparison.Ordinal) || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var code))
                throw new IOException("malformed HTTP response");
            var headers = new List<KeyValuePair<string, string>>();
            var total = 0;
            for (var line = await rd.LineAsync(ct).ConfigureAwait(false); line.Length > 0; line = await rd.LineAsync(ct).ConfigureAwait(false))
            {
                total += line.Length;
                if (total > MaxHeaderBytes) throw new IOException("response headers too large");
                var i = line.IndexOf(':', StringComparison.Ordinal);
                if (i <= 0) throw new IOException("malformed header");
                headers.Add(new(line[..i].Trim(), line[(i + 1)..].Trim()));
            }
            if (code is >= 100 and < 200) continue;                  // 100 Continue and friends
            var result = new HttpResult(code, headers, []);
            byte[] body;
            var te = result.Header("Transfer-Encoding");
            var cl = result.Header("Content-Length");
            if (te is not null && te.Contains("chunked", StringComparison.OrdinalIgnoreCase)) body = await rd.ChunkedAsync(MaxBodyBytes, ct).ConfigureAwait(false);
            else if (cl is not null)
            {
                if (!long.TryParse(cl, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n > MaxBodyBytes) throw new IOException("bad Content-Length");
                body = await rd.ExactAsync((int)n, ct).ConfigureAwait(false);
            }
            else body = await rd.ToEndAsync(MaxBodyBytes, ct).ConfigureAwait(false);
            return result with { Body = body };
        }
    }

    private sealed class Reader(Stream s)
    {
        private readonly byte[] _buf = new byte[16 * 1024];
        private int _pos, _len;

        private async Task<bool> FillAsync(CancellationToken ct)
        {
            _pos = 0;
            _len = await s.ReadAsync(_buf, ct).ConfigureAwait(false);
            return _len > 0;
        }

        public async Task<string> LineAsync(CancellationToken ct)
        {
            var sb = new StringBuilder();
            while (true)
            {
                if (_pos >= _len && !await FillAsync(ct).ConfigureAwait(false)) throw new IOException("connection closed");
                var b = _buf[_pos++];
                if (b == '\n') return sb.ToString().TrimEnd('\r');
                if (sb.Length > 8192) throw new IOException("line too long");
                sb.Append((char)b);
            }
        }

        public async Task<byte[]> ExactAsync(int n, CancellationToken ct)
        {
            var out_ = new byte[n];
            var o = 0;
            while (o < n)
            {
                if (_pos >= _len && !await FillAsync(ct).ConfigureAwait(false)) throw new IOException("connection closed early");
                var take = Math.Min(n - o, _len - _pos);
                Buffer.BlockCopy(_buf, _pos, out_, o, take);
                _pos += take; o += take;
            }
            return out_;
        }

        public async Task<byte[]> ChunkedAsync(long max, CancellationToken ct)
        {
            using var ms = new MemoryStream();
            while (true)
            {
                var sizeLine = (await LineAsync(ct).ConfigureAwait(false)).Split(';')[0].Trim();
                if (!long.TryParse(sizeLine, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var size) || size < 0) throw new IOException("bad chunk");
                if (size == 0)
                {
                    while ((await LineAsync(ct).ConfigureAwait(false)).Length > 0) { }   // trailers
                    return ms.ToArray();
                }
                if (ms.Length + size > max) throw new IOException("response too large");
                ms.Write(await ExactAsync((int)size, ct).ConfigureAwait(false));
                await LineAsync(ct).ConfigureAwait(false);
            }
        }

        public async Task<byte[]> ToEndAsync(long max, CancellationToken ct)
        {
            using var ms = new MemoryStream();
            ms.Write(_buf, _pos, _len - _pos);
            _pos = _len;
            while (await FillAsync(ct).ConfigureAwait(false))
            {
                ms.Write(_buf, 0, _len);
                if (ms.Length > max) throw new IOException("response too large");
            }
            return ms.ToArray();
        }
    }
}
