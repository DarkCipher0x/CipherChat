# Third-party software in CipherChat

CipherChat by DarkCipher Systems is MIT-licensed (LICENSE). It includes or depends on the following, under their own
licences. Versions are pinned; the hashes are checked when the builds fetch them.

| Component | Used by | Version | Licence |
|---|---|---|---|
| @noble/post-quantum (ML-KEM, ML-DSA) | web portal, call pages in the apps | 0.7.1 | MIT — `web/app/vendor/post-quantum/LICENSE` |
| @noble/curves (X25519, Ed25519) | web portal, call pages | 2.4.0 | MIT — `web/app/vendor/curves/LICENSE` |
| @noble/hashes (SHA-3, Argon2id) | web portal, call pages | 2.4.0 | MIT — `web/app/vendor/hashes/LICENSE` |
| Bouncy Castle for .NET (BouncyCastle.Cryptography) | Windows app (PQ TLS, crypto) | 2.7.0 | MIT (Bouncy Castle licence) |
| Bouncy Castle for Java (bcprov, bcutil, bctls) | Android app (crypto, PQ TLS) | 1.86 / 1.86.2 | MIT (Bouncy Castle licence) |
| Microsoft Edge WebView2 SDK | Windows app (call window) | 1.0.4191.47 | BSD-3-Clause (Microsoft) |
| .NET 8 runtime (self-contained in the Windows installer) | Windows app, Connector | 8.0 | MIT |
| System.Security.Cryptography.ProtectedData | Windows app, Connector (DPAPI) | 8.0 | MIT |
| AndroidX (Compose, Activity, Core, Biometric, Fragment, WebKit, Credentials), Kotlin, kotlinx.coroutines, kotlinx.serialization | Android app | see `android/gradle/libs.versions.toml` | Apache-2.0 |
| Google Play services code scanner, Credential Manager Play services provider | Android app (QR pairing, passkeys) | 16.1.0, 1.5.0 | Android Software Development Kit License |
| WiX Toolset (build only) | Windows installer | 5.0.2 | MS-RL (the installers it builds aren't covered) |

The Linux server uses only the Python standard library, nginx and coturn from the distribution's own packages.

Bouncy Castle licence: Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org).
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice
and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
