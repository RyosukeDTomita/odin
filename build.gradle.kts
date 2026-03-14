plugins {
    java
    id("com.gradleup.shadow") version "8.3.5"
    jacoco
}

group   = "com.odin.burp"
version = "0.0.1"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Provided at runtime by Burp Suite itself; excluded from fat JAR
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.mockito:mockito-core:5.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.shadowJar {
    archiveBaseName.set("odin")
    archiveClassifier.set("")
    archiveVersion.set(project.version.toString())
    minimize()
    destinationDirectory.set(layout.buildDirectory.asFile.get())
}

// Make 'build' produce the fat jar automatically
tasks.assemble {
    dependsOn(tasks.shadowJar)
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}
