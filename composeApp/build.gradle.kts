import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.composeMultiplatform)
    alias(libs.plugins.composeCompiler)
    alias(libs.plugins.composeHotReload)
}

kotlin {
    jvm()
    
    sourceSets {
        commonMain.dependencies {
            implementation(libs.compose.runtime)
            implementation(libs.compose.foundation)
            implementation(libs.compose.material3)
            implementation(libs.compose.ui)
            implementation(libs.compose.components.resources)
            implementation(libs.compose.uiToolingPreview)
            implementation(libs.androidx.lifecycle.viewmodelCompose)
            implementation(libs.androidx.lifecycle.runtimeCompose)
            implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.8.0-rc02")
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        jvmMain.dependencies {
            implementation(compose.desktop.currentOs)
            implementation(libs.kotlinx.coroutinesSwing)
            implementation(libs.rutoken.pkcs11jna)
            implementation("org.xerial:sqlite-jdbc:3.45.1.0")
            implementation("com.sun.mail:jakarta.mail:2.0.1")
            implementation("org.apache.poi:poi-ooxml:5.2.5")
        }
    }
}


compose.desktop {
    application {
        mainClass = "org.alex.project.MainKt"

        jvmArgs += listOf(
            "--add-modules", "java.smartcardio",
            "--add-modules", "java.security.jgss"
        )

        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb)
            packageName = "org.alex.project"
            packageVersion = "1.3.0"
        }
    }
}
