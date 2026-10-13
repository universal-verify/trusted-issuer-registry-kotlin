plugins {
    application
    kotlin("jvm") version "2.4.20"
}

kotlin { jvmToolchain(17) }
dependencies {
    implementation("com.universalverify:trusted-issuer-registry:0.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
}
application { mainClass.set("com.universalverify.consumer.Smoke") }
sourceSets.main {
    java.srcDir("../shared/src/main/java")
    resources.srcDir("../shared/src/main/resources")
}
dependencyLocking { lockAllConfigurations() }

tasks.register<JavaExec>("kotlinSmoke") {
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.universalverify.consumer.KotlinSmokeKt")
}
tasks.register("verifyJvmVariant") {
    doLast {
        val modules = configurations.runtimeClasspath.get().resolvedConfiguration.resolvedArtifacts.map { it.moduleVersion.id.name }
        check("okhttp-jvm" in modules && "okhttp-android" !in modules) { modules.toString() }
        check("icu4j" in modules) { "JVM name comparisons require ICU4J: $modules" }
    }
}
