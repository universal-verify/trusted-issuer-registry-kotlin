@file:OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)

import org.gradle.api.attributes.java.TargetJvmEnvironment
import org.gradle.api.attributes.java.TargetJvmVersion
import org.gradle.api.component.AdhocComponentWithVariants
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.dokka)
    `java-library`
    `maven-publish`
    signing
}

group = "com.universalverify"
version = "0.1.0"

kotlin {
    jvmToolchain(17)
    explicitApi()
    abiValidation {
        filters { exclude { byNames.add("com.universalverify.trustedissuerregistry.internal.**") } }
    }
}

java {
    withSourcesJar()
    withJavadocJar()
}

dokka {
    dokkaSourceSets.configureEach {
        jdkVersion.set(17)
    }
}
tasks.named<Jar>("javadocJar") {
    from(tasks.named("dokkaGeneratePublicationHtml"))
}

val sharedImplementation = configurations.create("sharedImplementation")
val sharedApi = configurations.create("sharedApi")
configurations.implementation { extendsFrom(sharedImplementation) }
configurations.api { extendsFrom(sharedApi) }

dependencies {
    api(libs.okhttp.jvm)
    // Android's ICU is built in; only JVM consumers need the ICU4J implementation.
    implementation(libs.icu4j)
    add(sharedApi.name, libs.serialization.core)
    add(sharedApi.name, kotlin("stdlib"))
    add(sharedImplementation.name, libs.coroutines)
    add(sharedImplementation.name, libs.serialization.json)
    add(sharedImplementation.name, libs.bcprov)
    add(sharedImplementation.name, libs.bcutil)
    add(sharedImplementation.name, libs.bcpkix)
    add(sharedImplementation.name, libs.canonical.numbers)
    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.mockwebserver)
    testRuntimeOnly(libs.junit.launcher)
}

dependencyLocking { lockAllConfigurations() }

// Both environments consume the same SDK JAR with their platform runtime dependencies.
val androidApi =
    configurations.create("androidApiElements") {
        isCanBeConsumed = true
        isCanBeResolved = false
        extendsFrom(sharedApi)
        attributes {
            attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage.JAVA_API))
            attribute(Category.CATEGORY_ATTRIBUTE, objects.named(Category.LIBRARY))
            attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, objects.named(LibraryElements.JAR))
            attribute(TargetJvmEnvironment.TARGET_JVM_ENVIRONMENT_ATTRIBUTE, objects.named(TargetJvmEnvironment.ANDROID))
            attribute(TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE, 17)
            attribute(KotlinPlatformType.attribute, KotlinPlatformType.androidJvm)
        }
        outgoing.artifact(tasks.jar)
    }
val androidRuntime =
    configurations.create("androidRuntimeElements") {
        isCanBeConsumed = true
        isCanBeResolved = false
        extendsFrom(sharedImplementation, configurations.runtimeOnly.get(), androidApi)
        attributes {
            attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage.JAVA_RUNTIME))
            attribute(Category.CATEGORY_ATTRIBUTE, objects.named(Category.LIBRARY))
            attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, objects.named(LibraryElements.JAR))
            attribute(TargetJvmEnvironment.TARGET_JVM_ENVIRONMENT_ATTRIBUTE, objects.named(TargetJvmEnvironment.ANDROID))
            attribute(TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE, 17)
            attribute(KotlinPlatformType.attribute, KotlinPlatformType.androidJvm)
        }
        outgoing.artifact(tasks.jar)
    }
// JVM-only OkHttp and ICU4J dependencies are not inherited by the Android publication.
dependencies {
    add(androidApi.name, libs.okhttp.android)
}
(components["java"] as AdhocComponentWithVariants).apply {
    addVariantsFromConfiguration(androidApi) { mapToOptional() }
    addVariantsFromConfiguration(androidRuntime) { mapToOptional() }
}

tasks.test {
    useJUnitPlatform()
    providers.gradleProperty("testJavaVersion").orNull?.toInt()?.let { version ->
        javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(version)) })
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("Trusted Issuer Registry")
                description.set("Resolve certificate trust using signed registry issuers and user-provided certificates")
                url.set("https://github.com/universal-verify/trusted-issuer-registry-kotlin")
                licenses {
                    license {
                        name.set("Mozilla Public License 2.0")
                        url.set("https://www.mozilla.org/MPL/2.0/")
                    }
                }
                developers {
                    developer {
                        id.set("universal-verify")
                        name.set("Universal Verify")
                        url.set("https://github.com/universal-verify")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/universal-verify/trusted-issuer-registry-kotlin.git")
                    developerConnection.set("scm:git:ssh://git@github.com/universal-verify/trusted-issuer-registry-kotlin.git")
                    url.set("https://github.com/universal-verify/trusted-issuer-registry-kotlin")
                }
                // Android variants are Gradle metadata only; Maven consumers use the JVM dependency.
                withXml {
                    val dependencies = asNode()["dependencies"] as groovy.util.NodeList
                    dependencies.filterIsInstance<groovy.util.Node>().forEach { parent ->
                        (parent["dependency"] as groovy.util.NodeList)
                            .filterIsInstance<groovy.util.Node>()
                            .filter { (it["artifactId"] as groovy.util.NodeList).text() == "okhttp-android" }
                            .forEach { parent.remove(it) }
                    }
                }
            }
        }
    }
    repositories {
        maven {
            name = "verification"
            url =
                layout.buildDirectory
                    .dir("repository")
                    .get()
                    .asFile
                    .toURI()
        }
        providers.gradleProperty("publishUrl").orNull?.let { destination ->
            maven {
                name = "release"
                url = uri(destination)
                credentials {
                    username = providers.environmentVariable("MAVEN_USERNAME").orNull
                    password = providers.environmentVariable("MAVEN_PASSWORD").orNull
                }
            }
        }
    }
}

signing {
    providers.environmentVariable("SIGNING_KEY").orNull?.let { key ->
        useInMemoryPgpKeys(key, providers.environmentVariable("SIGNING_PASSWORD").orNull)
        sign(publishing.publications["maven"])
    }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.register<Zip>("bundleForCentral") {
    dependsOn("publishMavenPublicationToVerificationRepository")
    val releaseVersion = project.version.toString()
    val artifactPath = "com/universalverify/trusted-issuer-registry/$releaseVersion"
    val directory =
        layout.buildDirectory
            .dir("repository/$artifactPath")
            .get()
            .asFile
    val signingConfigured = providers.environmentVariable("SIGNING_KEY").isPresent
    from(directory) { into(artifactPath) }
    archiveFileName.set("trusted-issuer-registry-$releaseVersion-central.zip")
    destinationDirectory.set(layout.buildDirectory.dir("central"))
    doFirst {
        val required = listOf(".jar", "-sources.jar", "-javadoc.jar", ".pom", ".module")
        check(signingConfigured && required.all { directory.resolve("trusted-issuer-registry-$releaseVersion$it.asc").isFile }) {
            "Set SIGNING_KEY and SIGNING_PASSWORD before assembling a signed Central Portal bundle"
        }
    }
}
