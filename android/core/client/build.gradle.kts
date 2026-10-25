// Pure JVM (no Android): the portal API, the PQ-only TLS transport, trust decisions and the chat engine. A Kotlin
// port of the Windows app's CipherChat.Transport / .Api / .Engine, so every client behaves the same; host-tested on the PC.
plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin { jvmToolchain(21) }
java {
    sourceCompatibility = JavaVersion.VERSION_17   // Android's desugared baseline
    targetCompatibility = JavaVersion.VERSION_17
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17); allWarningsAsErrors.set(true) }
}

dependencies {
    api(project(":core:crypto"))
    api(libs.kotlinx.coroutines.core)
    implementation(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.tls)
    implementation(libs.bouncycastle.util)
    testImplementation(libs.junit)
}

tasks.test {
    maxHeapSize = "1g"
    // live tests read CIPHERCHAT_DEV_* (a demo server through a tunnel) and skip themselves when they aren't set
    testLogging { events("failed", "skipped"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL; showStandardStreams = true }
}
