pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "CipherChat"

// App shell: wiring only.
include(":app")

// Core layers (arrows point down: feature -> core:* -> nothing above).
include(":core:crypto")       // pure JVM: the chat protocol's cryptography, byte-compatible with the web chat (BouncyCastle)
include(":core:client")       // pure JVM: portal API, trust decisions, rooms, room keys, sending (no Android, testable on the PC)
include(":core:security")     // Android: Keystore/StrongBox wrapping key, fingerprint prompts, the sealed vault
include(":core:designsystem") // Android: the DarkCipher theme (identical to Command and Studio) + shared components

// Features: each self-contained, never importing another feature.
include(":feature:gate")      // sign in, pair this phone, set up or unlock the chat identity, verify the owner
include(":feature:chat")      // rooms, direct messages, the terminal log, people and certificates
include(":feature:call")      // the call screen: a locked-down WebView running the shared call page (web/callhost)
