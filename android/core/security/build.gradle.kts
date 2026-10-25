// Android: the hardware-backed vault (Keystore / StrongBox key that needs a fingerprint or the screen lock for every
// use) that keeps this phone's pairings, and the prompts that unlock it.
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "systems.darkcipher.cipherchat.security"
    compileSdk = 36
    defaultConfig { minSdk = 31 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlin { jvmToolchain(21) }
}

dependencies {
    api(libs.androidx.biometric)
    api(libs.androidx.fragment)
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)
    testImplementation(libs.junit)
}
