using System.Text.Json.Nodes;
using CipherChat.Engine;

namespace CipherChat.Engine.Tests;

/// <summary>The warning for wraps the server should have deleted (PREKEYS-DESIGN §4.2).</summary>
public class LeftoverWrapTests
{
    [Fact]
    public void OnlyWrapsKeptPastTheGracePeriodCount()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), day = 86400;
        JsonObject It(long at, string? w) => new() { ["at"] = at, ["body"] = new JsonObject { ["w"] = w } };
        var items = new JsonArray(It(now - 30 * day, "x"), It(now - 9 * day, "x"), It(now - 7 * day - day / 2, "x"),
                                  It(now - 30 * day, null), It(now, "x"));
        Assert.Equal(2, KeyHistory.Leftover(items));
        Assert.Contains("2 copies", KeyHistory.LeftoverWarning(2));
        Assert.Contains("1 copy ", KeyHistory.LeftoverWarning(1));
    }
}
