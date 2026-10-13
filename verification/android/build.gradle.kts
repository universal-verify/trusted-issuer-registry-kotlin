plugins { id("com.android.application") version "9.4.1" }

val debugKeystore = layout.buildDirectory.file("debug.keystore").get().asFile
val prepareDebugKeystore = tasks.register<Exec>("prepareDebugKeystore") {
    outputs.file(debugKeystore)
    onlyIf { !debugKeystore.exists() }
    doFirst { debugKeystore.parentFile.mkdirs() }
    commandLine("keytool", "-genkeypair", "-keystore", debugKeystore.absolutePath,
        "-storetype", "JKS", "-storepass", "android", "-keypass", "android",
        "-alias", "AndroidDebugKey", "-dname", "CN=SDK Test,O=Universal Verify,C=US",
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000")
}
tasks.matching { it.name == "validateSigningRelease" }.configureEach { dependsOn(prepareDebugKeystore) }

android {
    namespace = "com.universalverify.consumer"
    compileSdk { version = release(37) { minorApiLevel = 2 } }
    defaultConfig {
        applicationId = "com.universalverify.consumer"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "com.universalverify.consumer.PublishedArtifactTest"
        testProguardFiles("test-proguard-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    testBuildType = "release"
    sourceSets.getByName("main") {
        java.directories.add("../shared/src/main/java")
        resources.directories.add("../shared/src/main/resources")
    }
    sourceSets.getByName("main").assets.directories.add("../../src/test/resources")
    signingConfigs.getByName("debug").storeFile = file("build/debug.keystore")
    packaging.resources.excludes += setOf("META-INF/LICENSE*", "META-INF/NOTICE*", "META-INF/versions/**")
}

if (!providers.gradleProperty("withoutSdk").isPresent) {
    dependencies { implementation("com.universalverify:trusted-issuer-registry:0.1.0") }
}
dependencyLocking { lockAllConfigurations() }

tasks.register("verifyAndroidVariant") {
    doLast {
        val modules = configurations.getByName("releaseRuntimeClasspath").resolvedConfiguration.resolvedArtifacts.map { it.moduleVersion.id.name }
        check("okhttp-android" in modules && "okhttp-jvm" !in modules) { modules.toString() }
        check("icu4j" !in modules) { "Android uses built-in ICU: $modules" }
    }
}

if (providers.gradleProperty("withoutSdk").isPresent) {
    configurations.configureEach { resolutionStrategy.deactivateDependencyLocking() }
    android.sourceSets.getByName("main") {
        java.directories.clear()
        resources.directories.clear()
        assets.directories.clear()
    }
}
