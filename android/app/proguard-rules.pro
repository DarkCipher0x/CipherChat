# BouncyCastle looks some algorithms up by name; keep its providers and the TLS/PQC classes it reflects on.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
# Credential Manager's Play Services provider is loaded reflectively.
-if class androidx.credentials.CredentialManager
-keep class androidx.credentials.playservices.** { *; }
