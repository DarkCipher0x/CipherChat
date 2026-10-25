// The call screen: a locked-down WebView running the call page shared with the Windows app (web/callhost) and the
// web portal's call engine (web/app), served from inside the APK. The page asks this module for every step that
// needs the identity (Calls.kt in core:client), so private keys never enter the WebView.
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "systems.darkcipher.cipherchat.call"
    compileSdk = 36
    defaultConfig { minSdk = 31 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlin { jvmToolchain(21) }
    buildFeatures { compose = true }
    sourceSets["main"].assets.srcDir(layout.buildDirectory.dir("generated/callassets"))
}

// The same files the Windows app ships in CallHost/ (CipherChat.App.csproj), copied fresh on every build.
val web = rootDir.resolve("../web")
val callAssets by tasks.registering(Sync::class) {
    into(layout.buildDirectory.dir("generated/callassets/callhost"))
    from(web.resolve("callhost"))
    into("app") {
        from(web.resolve("app")) {
            include("crypto.js", "kat.js", "callcrypto.js", "call.js", "callworker.js", "callui.js", "glitch.js", "term.js", "chat.css", "vendor/**")
        }
    }
}
tasks.named("preBuild") { dependsOn(callAssets) }

dependencies {
    implementation(project(":core:client"))
    implementation(project(":core:designsystem"))
    implementation(libs.androidx.webkit)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.kotlinx.coroutines.android)
}
