// Pure JVM (no Android): runs unchanged on the phone and in fast host tests on the PC.
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
    api(libs.kotlinx.serialization.json)
    implementation(libs.bouncycastle.prov)
    testImplementation(libs.junit)
}

tasks.test {
    // Argon2id at 64 MiB per derivation
    maxHeapSize = "1g"
    testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL; showStandardStreams = true }
}
