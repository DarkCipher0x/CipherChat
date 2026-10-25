// The app shell: wiring only (the screens live in feature:*, the protocol in core:*).
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "systems.darkcipher.cipherchat"
    compileSdk = 36
    buildFeatures { buildConfig = true; compose = true }

    defaultConfig {
        applicationId = "systems.darkcipher.cipherchat"
        minSdk = 31          // Android 12: StrongBox/TEE keys with per-use biometric or screen-lock authentication
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.1"
    }

    signingConfigs {
        // Release signing comes from the environment (the keystore never lives in the repo); see tools/release.ps1.
        create("release") {
            val ks = System.getenv("CIPHERCHAT_KEYSTORE")
            if (ks != null) {
                storeFile = file(ks)
                storePassword = System.getenv("CIPHERCHAT_KEYSTORE_PASS")
                keyAlias = System.getenv("CIPHERCHAT_KEY_ALIAS")
                keyPassword = System.getenv("CIPHERCHAT_KEY_PASS")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlin { jvmToolchain(21) }
    // BouncyCastle's three jars each carry the same licence and OSGi manifest: keep one copy
    packaging { resources { pickFirsts += setOf("META-INF/LICENSE.md", "META-INF/LICENSE", "META-INF/versions/9/OSGI-INF/MANIFEST.MF") } }
}

dependencies {
    implementation(project(":core:client"))
    implementation(project(":core:security"))
    implementation(project(":core:designsystem"))
    implementation(project(":feature:gate"))
    implementation(project(":feature:chat"))
    implementation(project(":feature:call"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play)
    implementation(libs.kotlinx.coroutines.android)
}
