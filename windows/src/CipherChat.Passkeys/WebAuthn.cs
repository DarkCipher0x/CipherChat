using System.Runtime.InteropServices;

namespace CipherChat.Passkeys;

/// <summary>
/// The parts of webauthn.h (Windows SDK) that a passkey sign-in needs: version 1 of each structure, which every
/// Windows 10 1903+ webauthn.dll accepts. Field order and types follow the header exactly.
/// </summary>
internal static class WebAuthn
{
    public const uint ClientDataVersion1 = 1;
    public const uint CredentialVersion1 = 1;
    public const uint GetAssertionOptionsVersion1 = 1;
    public const uint AttachmentAny = 0;
    public const uint UserVerificationRequired = 1;
    public const int UserCancelled = unchecked((int)0x800704C7);   // HRESULT_FROM_WIN32(ERROR_CANCELLED)
    public const int NteUserCancelled = unchecked((int)0x80090036);
    public const int NteNotFound = unchecked((int)0x80090011);

    [StructLayout(LayoutKind.Sequential)]
    public struct ClientData
    {
        public uint dwVersion;
        public uint cbClientDataJSON;
        public IntPtr pbClientDataJSON;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszHashAlgId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Credential
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public IntPtr pwszCredentialType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Credentials
    {
        public uint cCredentials;
        public IntPtr pCredentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Extensions
    {
        public uint cExtensions;
        public IntPtr pExtensions;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct GetAssertionOptions
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public Credentials CredentialList;
        public Extensions Extensions;
        public uint dwAuthenticatorAttachment;
        public uint dwUserVerificationRequirement;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Assertion
    {
        public uint dwVersion;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbSignature;
        public IntPtr pbSignature;
        public Credential Credential;
        public uint cbUserId;
        public IntPtr pbUserId;
    }

    [DllImport("webauthn.dll", ExactSpelling = true)]
    public static extern uint WebAuthNGetApiVersionNumber();

    [DllImport("webauthn.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    public static extern int WebAuthNAuthenticatorGetAssertion(IntPtr hWnd, string pwszRpId, ref ClientData pWebAuthNClientData,
                                                               ref GetAssertionOptions pWebAuthNGetAssertionOptions, out IntPtr ppWebAuthNAssertion);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    public static extern void WebAuthNFreeAssertion(IntPtr pWebAuthNAssertion);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    public static extern IntPtr WebAuthNGetErrorName(int hr);
}
