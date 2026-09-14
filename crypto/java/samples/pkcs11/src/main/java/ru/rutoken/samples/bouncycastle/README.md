# Примеры BouncyCastle

## Known issues
If `CmsEncryptDecryptGOSTR3410_*` samples are run on jre 8 version older than 161 (which forbids usage of keys longer than 128 bits by default - search "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files"), these samples wouldn't work properly. Consider migrating to jre 8 161 or newer, or manually replace file `<path_to_jre>/lib/security/local_policy.jar` with newer file `local_policy.jar` that you can download from [oracle website](https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).
