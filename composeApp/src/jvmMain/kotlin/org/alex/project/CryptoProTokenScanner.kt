package org.alex.project

/**
 * Резервный способ опроса носителей — разбор вывода утилит КриптоПро CSP.
 * Используется, только если библиотека PKCS#11 недоступна или не нашла сертификатов.
 */
object CryptoProTokenScanner {
    private const val CSPTEST = "C:\\Program Files\\Crypto Pro\\CSP\\csptest.exe"
    private const val CERTMGR = "C:\\Program Files\\Crypto Pro\\CSP\\certmgr.exe"
    private const val CONSOLE_CHARSET = "CP866"

    fun scanAllTokens(): List<CertInfo> {
        val resultList = mutableListOf<CertInfo>()
        val remainingHardware = getHardwareSerials().toMutableList()

        try {
            val containers = ProcessBuilder(
                CSPTEST, "-keyset", "-enum_cont", "-verifycontext", "-fqcn", "-machine"
            ).start().inputStream.bufferedReader(charset(CONSOLE_CHARSET)).readLines()
                .filter { it.contains("\\\\.\\") }
                .map { it.trim() }

            containers.forEach { path ->
                val readerName = path.substringAfter("\\\\.\\").substringBefore("\\").trim()
                val containerName = path.substringAfterLast("\\").trim()

                // Сплошной кусок цифр длиной 9-13 знаков — обычно номер носителя в имени контейнера.
                val code = """\d{9,13}""".toRegex().find(containerName)?.value
                    ?: """\d+""".toRegex().find(containerName)?.value
                    ?: readerName

                val matchIndex = remainingHardware.indexOfFirst { pair ->
                    pair.first.contains(code, true) || code.contains(pair.first, true)
                }

                val realSerial = when {
                    matchIndex != -1 -> remainingHardware.removeAt(matchIndex).second
                    remainingHardware.isNotEmpty() -> remainingHardware.removeAt(0).second
                    else -> "ID не найден"
                }

                val info = fetchInfoDirectly(path)
                resultList.add(info.copy(hardwareId = realSerial, containerPath = path))
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return resultList
    }

    private fun getHardwareSerials(): List<Pair<String, String>> {
        val list = mutableListOf<Pair<String, String>>()
        try {
            val process = ProcessBuilder(
                "certutil",
                "-silent",
                "-csp",
                "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
                "-key"
            ).start()
            val regex = """rutoken(?:_ecp)?_([a-fA-F0-9]+)""".toRegex()
            process.inputStream.bufferedReader(charset(CONSOLE_CHARSET)).useLines { lines ->
                var lastId = ""
                lines.forEach { line ->
                    extractKeyIds(line.trim()).firstOrNull()?.let { lastId = it }

                    if (line.contains("SCARD\\")) {
                        regex.find(line)?.groupValues?.get(1)?.let { hex ->
                            val code = hex.toLong(16).toString()
                            if (lastId.isNotEmpty()) {
                                list.add(Pair(lastId, code))
                                lastId = ""
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return list
    }

    private fun fetchInfoDirectly(path: String): CertInfo {
        var subject = CertificateParser.UNKNOWN
        var validFrom = CertificateParser.UNKNOWN
        var validTo = CertificateParser.UNKNOWN
        var mailTo = CertificateParser.UNKNOWN
        var inn = CertificateParser.UNKNOWN
        var snils = CertificateParser.UNKNOWN
        var jobTitle = CertificateParser.UNKNOWN

        try {
            val process = ProcessBuilder(CERTMGR, "-list", "-container", path).start()
            process.inputStream.bufferedReader(charset(CONSOLE_CHARSET)).useLines { lines ->
                lines.forEach { line ->
                    val l = line.trim()
                    if (l.startsWith("Субъект")) {
                        if (l.contains("CN=")) subject = l.substringAfter("CN=").substringBefore(",")
                        if (l.contains("E=")) mailTo = l.substringAfter("E=").substringBefore(",")
                        if (l.contains("ИНН=")) inn = l.substringAfter("ИНН=").substringBefore(",")
                        if (l.contains("СНИЛС=")) snils = l.substringAfter("СНИЛС=").substringBefore(",")
                        if (l.contains("T=")) jobTitle = l.substringAfter("T=").substringBefore(",")
                    }

                    if (l.startsWith("Выдан")) {
                        validFrom = l.substringAfter(":").substringBefore("UTC").trim()
                            .substringBefore(" ").replace("/", ".")
                    }

                    if (l.startsWith("Истекает")) {
                        validTo = l.substringAfter(":").substringBefore("UTC").trim()
                            .substringBefore(" ").replace("/", ".")
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return CertInfo(subject, validFrom, validTo, mailTo, inn, snils, jobTitle)
    }

    private fun extractKeyIds(input: String): List<String> =
        Regex("""\d{8,13}""").findAll(input).map { it.value }.distinct().toList()
}
