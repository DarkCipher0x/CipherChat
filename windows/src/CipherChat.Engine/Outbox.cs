using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;

namespace CipherChat.Engine;

/// <summary>
/// A message on its way to the server (Outbox.kt on Android, the same rules). It survives bad networks: it is sealed
/// once and resent unchanged until the server has it (the server recognises a resend by its signed message id, so a
/// send whose answer was lost never turns into two messages), and it is only re-sealed when the server says the room
/// key changed and it hasn't got it.
/// </summary>
public sealed class Outgoing
{
    public enum States { Queued, Sending, Sent, Failed }

    internal Outgoing(Room room, string kind, string preview, JsonObject @base, IReadOnlyList<ChatEngine.OutgoingFile> files)
    {
        Room = room; Kind = kind; Preview = preview; Base = @base; Files = files;
    }

    public Room Room { get; }
    /// <summary>text | me | file | react | edit</summary>
    public string Kind { get; }
    /// <summary>What the timeline shows while it waits.</summary>
    public string Preview { get; }
    public States State { get; internal set; } = States.Queued;
    /// <summary>Why it failed (a refusal retrying can't fix), or what's happening while it waits.</summary>
    public string? Note { get; internal set; }
    public int Attempts { get; internal set; }
    public bool Visible => Kind is "text" or "me" or "file";

    internal JsonObject Base { get; }
    internal IReadOnlyList<ChatEngine.OutgoingFile> Files { get; }
    internal Entry? Entry { get; set; }
    internal readonly List<JsonObject> Uploaded = [];
    internal readonly List<string> Blobs = [];
    internal CipherChat.Crypto.Room.SealedMsg? Sealed { get; set; }
    internal string? MsgId { get; set; }
}

/// <summary>
/// The engine's outbox: one worker sends queued messages in order. Offline, timeouts, server errors and rate limits are
/// waited out (1 s doubling to 30 s, and at once when the connection comes back); a refusal retrying can't fix marks the
/// message failed, with Retry and Discard. The app may keep <see cref="Snapshot"/> (sealed text messages) in its vault
/// across a lock and hand it back to <see cref="Restore"/>.
/// </summary>
internal sealed class Outbox(ChatEngine e)
{
    private readonly List<Outgoing> _items = [];
    private readonly SemaphoreSlim _kick = new(0, 1);

    public IReadOnlyList<Outgoing> Pending { get { lock (_items) return _items.ToList(); } }

    public void Start(CancellationToken ct) => _ = Task.Run(() => LoopAsync(ct), ct);

    public void Add(Outgoing o)
    {
        lock (_items) _items.Add(o);
        Wake();
    }

    public void Wake()
    {
        try { if (_kick.CurrentCount == 0) _kick.Release(); } catch (SemaphoreFullException) { }
    }

    public void Retry(Outgoing o)
    {
        if (o.State != Outgoing.States.Failed) return;
        o.State = Outgoing.States.Queued; o.Note = null;
        e.OutgoingChanged(o);
        Wake();
    }

    public bool Discard(Outgoing o)
    {
        if (o.State is Outgoing.States.Sending or Outgoing.States.Sent) return false;
        lock (_items) _items.Remove(o);
        e.OutgoingGone(o);
        return true;
    }

    /// <summary>The real message arrived from the server: its placeholder goes.</summary>
    public void Delivered(string msgId)
    {
        Outgoing? o;
        lock (_items)
        {
            o = _items.FirstOrDefault(x => x.MsgId == msgId);
            if (o is not null) _items.Remove(o);
        }
        if (o is null) return;
        o.State = Outgoing.States.Sent;
        e.OutgoingGone(o);
    }

    private enum Result { Sent, Later, Failed }

    private async Task LoopAsync(CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        while (!ct.IsCancellationRequested)
        {
            Outgoing? next;
            lock (_items) next = _items.FirstOrDefault(x => x.State == Outgoing.States.Queued);
            try
            {
                if (next is null) { await _kick.WaitAsync(ct).ConfigureAwait(false); continue; }
                switch (await AttemptAsync(next).ConfigureAwait(false))
                {
                    case Result.Sent:
                        backoff = TimeSpan.FromSeconds(1);
                        if (!next.Visible) { lock (_items) _items.Remove(next); e.OutgoingGone(next); }
                        break;
                    case Result.Later:
                        next.State = Outgoing.States.Queued;
                        next.Note = "waiting for the connection";
                        e.OutgoingChanged(next);
                        await _kick.WaitAsync(backoff, ct).ConfigureAwait(false);
                        backoff = TimeSpan.FromSeconds(Math.Min(30, backoff.TotalSeconds * 2));
                        break;
                    case Result.Failed:
                        e.OutgoingChanged(next);
                        break;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
        }
    }

    private static bool Transient(ApiException x) => x.Offline || x.Status >= 500 || x.Status is 429 or 408;

    private async Task<Result> AttemptAsync(Outgoing o)
    {
        o.State = Outgoing.States.Sending;
        o.Attempts++;
        o.Note = null;
        e.OutgoingChanged(o);
        var r = o.Room;
        try
        {
            for (var i = o.Uploaded.Count; i < o.Files.Count; i++)                 // each attachment uploaded once
            {
                o.Note = "uploading " + (i + 1) + "/" + o.Files.Count;
                e.OutgoingChanged(o);
                var (refJson, blobs) = await e.UploadFileAsync(r, o.Files[i]).ConfigureAwait(false);
                o.Uploaded.Add(refJson); o.Blobs.AddRange(blobs);
            }
            var payload = (JsonObject)o.Base.DeepClone();
            if (o.Files.Count > 0) payload["files"] = new JsonArray(o.Uploaded.Select(x => (JsonNode)x.DeepClone()).ToArray());
            for (var attempt = 0; attempt < 3; attempt++)
            {
                if (o.Sealed is null)
                {
                    o.Sealed = await e.SealAsync(r, payload).ConfigureAwait(false);
                    o.MsgId = Canon.ParseSigned(o.Sealed.H, 4096).Obj.Str("id");
                }
                try
                {
                    await e.Api.CallAsync("rooms/" + r.Id + "/send", new JsonObject
                    {
                        ["msg"] = new JsonObject { ["h"] = o.Sealed.H, ["c"] = o.Sealed.C, ["s"] = o.Sealed.S },
                        ["blobs"] = new JsonArray(o.Blobs.Select(b => (JsonNode)b).ToArray()), ["burn"] = payload.ContainsKey("burn"),
                    }).ConfigureAwait(false);
                    o.State = Outgoing.States.Sent; e.OutgoingChanged(o);
                    return Result.Sent;
                }
                catch (ApiException x) when (x.Flag("duplicate"))
                {
                    o.State = Outgoing.States.Sent; e.OutgoingChanged(o);
                    return Result.Sent;
                }
                catch (ApiException x) when (x.Flag("rotate") || x.Flag("stale"))
                {
                    await e.RefreshAsync().ConfigureAwait(false);                    // re-seal under the new key
                    o.Sealed = null; o.MsgId = null;
                }
            }
            return Result.Later;                                                   // the room kept changing: try again shortly
        }
        catch (ApiException x) { return Transient(x) ? Result.Later : Fail(o, x.Message); }
        catch (IOException) { return Result.Later; }
        catch (Exception x) when (x is CryptoFail or InvalidOperationException or ArgumentException) { return Fail(o, x.Message); }
    }

    private static Result Fail(Outgoing o, string? why)
    {
        o.State = Outgoing.States.Failed;
        o.Note = why ?? "the server refused it";
        return Result.Failed;
    }

    // ------------------------------------------------------------------------------------------- across a lock
    /// <summary>Text messages still waiting (sealed where they already were); attachments aren't kept.</summary>
    public JsonArray Snapshot()
    {
        var a = new JsonArray();
        foreach (var o in Pending.Where(x => x.Files.Count == 0 && x.State != Outgoing.States.Sent))
        {
            var j = new JsonObject { ["room"] = o.Room.Id, ["kind"] = o.Kind, ["preview"] = o.Preview, ["payload"] = o.Base.DeepClone() };
            if (o.Sealed is { } s) j["sealed"] = new JsonObject { ["h"] = s.H, ["c"] = s.C, ["s"] = s.S };
            a.Add(j);
        }
        return a;
    }

    public int DroppedOnLock => Pending.Count(x => x.Files.Count > 0 && x.State != Outgoing.States.Sent);

    public void Restore(JsonArray saved)
    {
        foreach (var j in saved.OfType<JsonObject>())
        {
            var r = e.RoomById(j.StrOrNull("room") ?? "");
            if (r is null || j["payload"] is not JsonObject payload) continue;
            var o = new Outgoing(r, j.StrOrNull("kind") ?? "text", j.StrOrNull("preview") ?? "", (JsonObject)payload.DeepClone(), []);
            if (j["sealed"] is JsonObject s)
            {
                o.Sealed = new CipherChat.Crypto.Room.SealedMsg(s.Str("h"), s.Str("c"), s.Str("s"));
                o.MsgId = Canon.ParseSigned(o.Sealed.H, 4096).Obj.Str("id");
            }
            e.OutgoingAdded(o);
            Add(o);
        }
    }
}
