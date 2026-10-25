using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;

namespace CipherChat.Passkeys;

/// <summary>A passkey sign-in Windows refused (not cancelled: that returns null).</summary>
public sealed class PasskeyException(string message) : Exception(message);

/// <summary>
/// Turns the server's WebAuthn request options into a signed assertion with Windows' passkey picker. The
/// clientDataJSON is built here exactly as a browser builds it for <c>origin</c>, so the server's checks (challenge,
/// origin, RP ID hash, user verification, signature, counter) are the same as for the web chat.
/// </summary>
public static class WindowsPasskey
{
    /// <summary>True when this Windows has the WebAuthn API (Windows 10 1903 and later).</summary>
    public static bool Available
    {
        get
        {
            try { return WebAuthn.WebAuthNGetApiVersionNumber() >= 1; }
            catch (DllNotFoundException) { return false; }
            catch (EntryPointNotFoundException) { return false; }
        }
    }

    /// <summary>
    /// Shows Windows' passkey dialog (owned by <paramref name="window"/>) and returns the PublicKeyCredential JSON,
    /// or null if the person cancelled or has no passkey here. Blocks until they finish, so call it off the UI thread.
    /// </summary>
    public static JsonObject? Sign(IntPtr window, JsonObject publicKey, string origin)
    {
        var rpId = publicKey["rpId"]?.GetValue<string>() ?? throw new PasskeyException("The server sent no RP ID.");
        var challenge = publicKey["challenge"]?.GetValue<string>() ?? throw new PasskeyException("The server sent no challenge.");
        var timeout = publicKey["timeout"] is JsonValue t ? (uint)Math.Clamp(t.GetValue<long>(), 30_000, 600_000) : 300_000u;
        // the same members, in the same order, as a browser's clientDataJSON
        var clientJson = Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"challenge\":" + JsonValue.Create(challenge).ToJsonString() +
                                                ",\"origin\":" + JsonValue.Create(origin).ToJsonString() + ",\"crossOrigin\":false}");
        var allow = (publicKey["allowCredentials"] as JsonArray ?? []).OfType<JsonObject>()
            .Select(c => B64u.Decode(c["id"]!.GetValue<string>())).ToList();

        var pins = new List<GCHandle>();
        var typeName = Marshal.StringToHGlobalUni("public-key");
        IntPtr credArray = IntPtr.Zero, assertion = IntPtr.Zero;
        try
        {
            IntPtr Pin(byte[] b) { var h = GCHandle.Alloc(b, GCHandleType.Pinned); pins.Add(h); return h.AddrOfPinnedObject(); }
            var cd = new WebAuthn.ClientData
            {
                dwVersion = WebAuthn.ClientDataVersion1, cbClientDataJSON = (uint)clientJson.Length, pbClientDataJSON = Pin(clientJson), pwszHashAlgId = "SHA-256",
            };
            var size = Marshal.SizeOf<WebAuthn.Credential>();
            if (allow.Count > 0)
            {
                credArray = Marshal.AllocHGlobal(size * allow.Count);
                for (var i = 0; i < allow.Count; i++)
                {
                    Marshal.StructureToPtr(new WebAuthn.Credential
                    {
                        dwVersion = WebAuthn.CredentialVersion1, cbId = (uint)allow[i].Length, pbId = Pin(allow[i]), pwszCredentialType = typeName,
                    }, credArray + i * size, false);
                }
            }
            var opts = new WebAuthn.GetAssertionOptions
            {
                dwVersion = WebAuthn.GetAssertionOptionsVersion1,
                dwTimeoutMilliseconds = timeout,
                CredentialList = new WebAuthn.Credentials { cCredentials = (uint)allow.Count, pCredentials = credArray },
                dwAuthenticatorAttachment = WebAuthn.AttachmentAny,
                dwUserVerificationRequirement = WebAuthn.UserVerificationRequired,  // the server refuses anything less
            };
            var hr = WebAuthn.WebAuthNAuthenticatorGetAssertion(window, rpId, ref cd, ref opts, out assertion);
            if (hr is WebAuthn.UserCancelled or WebAuthn.NteUserCancelled or WebAuthn.NteNotFound) return null;
            if (hr != 0) throw new PasskeyException("Windows couldn't use a passkey (" + ErrorName(hr) + ").");

            var a = Marshal.PtrToStructure<WebAuthn.Assertion>(assertion);
            var id = Copy(a.Credential.pbId, a.Credential.cbId);
            var response = new JsonObject
            {
                ["clientDataJSON"] = B64u.Encode(clientJson),
                ["authenticatorData"] = B64u.Encode(Copy(a.pbAuthenticatorData, a.cbAuthenticatorData)),
                ["signature"] = B64u.Encode(Copy(a.pbSignature, a.cbSignature)),
            };
            if (a.cbUserId > 0) response["userHandle"] = B64u.Encode(Copy(a.pbUserId, a.cbUserId));
            return new JsonObject { ["id"] = B64u.Encode(id), ["rawId"] = B64u.Encode(id), ["type"] = "public-key", ["response"] = response };
        }
        finally
        {
            if (assertion != IntPtr.Zero) WebAuthn.WebAuthNFreeAssertion(assertion);
            if (credArray != IntPtr.Zero) Marshal.FreeHGlobal(credArray);
            Marshal.FreeHGlobal(typeName);
            foreach (var h in pins) h.Free();
        }
    }

    private static byte[] Copy(IntPtr p, uint n)
    {
        var b = new byte[n];
        if (n > 0) Marshal.Copy(p, b, 0, (int)n);
        return b;
    }

    private static string ErrorName(int hr)
    {
        try
        {
            var p = WebAuthn.WebAuthNGetErrorName(hr);
            if (p != IntPtr.Zero) return Marshal.PtrToStringUni(p) ?? hr.ToString("X8");
        }
        catch (EntryPointNotFoundException) { }
        return "0x" + hr.ToString("X8");
    }
}

internal static class B64u
{
    public static string Encode(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t.PadRight(t.Length + (4 - t.Length % 4) % 4, '='));
    }
}
