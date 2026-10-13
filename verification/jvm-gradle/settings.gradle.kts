pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
dependencyResolutionManagement {
    repositories {
        maven { url = uri("../../build/repository") }
        mavenCentral()
    }
}
rootProject.name = "jvm-consumer"
