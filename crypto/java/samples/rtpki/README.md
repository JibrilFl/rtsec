# Java-библиотека rtpki

## Описание

Java-библиотека rtpki предназначена для шифрования и расшифрования CMS с использованием Рутокена по следующим
алгоритмам:

* ГОСТ 34.12-2018 «Магма» в режимах CTR-ACPKM и CTR-ACPKM-OMAC;
* ГОСТ 34.12-2018 «Кузнечик» в режимах CTR-ACPKM и CTR-ACPKM-OMAC;
* ГОСТ 28147-89;
* AES с длиной ключа 128, 192 и 256 бит в режиме CBC.

## Как добавить rtpki в проект

Библиотека rtpki включает в себя следующие артефакты, доступные на Maven Central:

* [ru.rutoken.rtpki:rtpki-jvm](https://central.sonatype.com/artifact/ru.rutoken.rtpki/rtpki-jvm) - библиотека для
  desktop-приложений с поддержкой ОС Windows x86/x86_64, Linux x86/x86_64 и macOS arm64/x86_64;
* [ru.rutoken.rtpki:rtpki-android](https://central.sonatype.com/artifact/ru.rutoken.rtpki/rtpki-android) - библиотека
  для Android-приложений с поддержкой arm64 и armv7a архитектур.

### Пример для Gradle

Desktop:

```kotlin
dependencies {
    implementation("ru.rutoken.rtpki:rtpki-jvm:${rtpkiVersion}")
}
```

Android:

```kotlin
dependencies {
    implementation("ru.rutoken.rtpki:rtpki-android:${rtpkiVersion}")
}
```

Библиотека rtpki транзитивно подключает
артефакты [ru.rutoken.rtpki:rtpki-jvm-support](https://central.sonatype.com/artifact/ru.rutoken.rtpki/rtpki-jvm-support)
и [ru.rutoken.rtpki:rtpki-android-support](https://central.sonatype.com/artifact/ru.rutoken.rtpki/rtpki-android-support),
содержащие динамические библиотеки OpenSSL (а именно crypto) и rtengine под desktop и Android соответственно. Также
rtpki транзитивно подключает библиотеку JNA.

> **Примечание**: Работоспособность библиотеки rtpki гарантирована только с версиями OpenSSL и rtengine из
> support-зависимостей.

В случае, если в Вашем проекте используются свои OpenSSL и rtengine И/ИЛИ JNA, необходимо подключать библиотеку rtpki
следующим образом:

Desktop:

```kotlin
dependencies {
    implementation("ru.rutoken.rtpki:rtpki-jvm:${rtpkiVersion}") {
        // Если в Вашем проекте используются собственные версии OpenSSL и rtengine
        exclude("ru.rutoken.rtpki", "rtpki-jvm-support")
        // Если в Вашем проекте уже подключена JNA
        exclude("net.java.dev.jna", "jna")
    }
}
```

Android:

```kotlin
dependencies {
    implementation("ru.rutoken.rtpki:rtpki-android:${rtpkiVersion}") {
        // Если в Вашем проекте используются собственные версии OpenSSL и rtengine
        exclude("ru.rutoken.rtpki", "rtpki-android-support")
        // Если в Вашем проекте уже подключена JNA
        exclude("net.java.dev.jna", "jna")
    }
}
```

Также возможны следующие сценарии использования:

1. Вы хотите использовать только одну собственную нативную библиотеку, а вторую брать из support-зависимости.
2. Вы уже используете maven-зависимость, которая содержит внутри себя OpenSSL и/или rtengine.

В этих случаях можно воспользоваться стратегиями упаковки артефактов и порядком объявления зависимостей. Таким образом
получится отфильтровать нативные библиотеки, оставив только необходимые:

Desktop:

```kotlin
tasks.jar {
    // Игнорируем дубликаты файлов, если аналогичные уже встречались ранее в графе зависимостей
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

dependencies {
    // Объявляем зависимость с OpenSSL и/или rtengine до объявления rtpki
    implementation("com.example:library-with-duplicate:${version}")
    // OpenSSL и/или rtengine из rtpki будут проигнорированы
    implementation("ru.rutoken.rtpki:rtpki-jvm:${rtpkiVersion}")
}
```

Android:

```kotlin
android {
    packaging {
        // Добавляем в артефакт только первую нативную библиотеку в графе зависимостей
        jniLibs.pickFirsts.add("**/libcrypto.so")
        jniLibs.pickFirsts.add("**/librtengine.so")
    }
}

dependencies {
    // Объявляем зависимость с OpenSSL и/или rtengine до объявления rtpki
    implementation("com.example:library-with-duplicate:${version}")
    // OpenSSL и/или rtengine из rtpki будут проигнорированы
    implementation("ru.rutoken.rtpki:rtpki-android:${rtpkiVersion}")
}
```

## Примеры использования

### Desktop

Для демонстрации работы библиотеки rtpki сделаны два примера:

* _**RtPkiEncryptSample.java**_ - демонстрирует шифрование CMS с использованием алгоритма ГОСТ 34.12-2018 «Кузнечик».
  Для этого примера не требуется подключенный Рутокен.
* _**RtPkiDecryptSample.java**_ - демонстрирует шифрование и расшифрование CMS с использованием алгоритма ГОСТ 34.12-2018
  «Магма». Для этого примера требуется подключить Рутокен ЭЦП 3.0.

### Android

Примеры работы с библиотекой rtpki для Android представлены в рамках
проекта [Рутокен Технологии](https://github.com/AktivCo/rutoken-tech-android). В разделе «Банк» при работе с Рутокен ЭЦП
3.0 шифрование и расшифрование CMS происходит с использованием алгоритма ГОСТ 34.12-2018 «Магма».
