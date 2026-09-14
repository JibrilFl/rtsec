package org.alex.project

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.naming.ldap.LdapName
import javax.security.auth.x500.X500Principal

/** Разбор X.509 из DER в модель журнала. */
object CertificateParser {
    const val UNKNOWN = "Неизвестно"

    private const val OID_COMMON_NAME = "2.5.4.3"
    private const val OID_TITLE = "2.5.4.12"
    private const val OID_EMAIL = "1.2.840.113549.1.9.1"
    private const val OID_INN = "1.2.643.3.131.1.1"
    private const val OID_INN_LE = "1.2.643.100.4"
    private const val OID_SNILS = "1.2.643.100.3"

    private const val SAN_RFC822_NAME = 1

    /** RFC 2253 печатает часть атрибутов сокращениями, остальные — числовым OID. */
    private val KEYWORD_OIDS = mapOf(
        "cn" to OID_COMMON_NAME,
        "t" to OID_TITLE,
        "title" to OID_TITLE,
        "e" to OID_EMAIL,
        "emailaddress" to OID_EMAIL
    )

    private val DATE_FORMAT get() = SimpleDateFormat("dd.MM.yyyy", Locale("ru"))

    fun parse(derCertificate: ByteArray, hardwareId: String, containerPath: String): CertInfo {
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(derCertificate)) as X509Certificate
        return parse(certificate, hardwareId, containerPath)
    }

    fun parse(certificate: X509Certificate, hardwareId: String, containerPath: String): CertInfo {
        val subject = subjectAttributes(certificate.subjectX500Principal)
        return CertInfo(
            subject = subject[OID_COMMON_NAME] ?: UNKNOWN,
            validFrom = formatDate(certificate.notBefore),
            validTo = formatDate(certificate.notAfter),
            mailTo = subject[OID_EMAIL] ?: emailFromSubjectAlternativeNames(certificate) ?: UNKNOWN,
            inn = subject[OID_INN] ?: subject[OID_INN_LE] ?: UNKNOWN,
            snils = subject[OID_SNILS] ?: UNKNOWN,
            jobTitle = subject[OID_TITLE] ?: UNKNOWN,
            hardwareId = hardwareId,
            containerPath = containerPath
        )
    }

    private fun formatDate(date: Date): String = DATE_FORMAT.format(date)

    internal fun subjectAttributes(principal: X500Principal): Map<String, String> =
        LdapName(principal.getName(X500Principal.RFC2253)).rdns
            .flatMap { rdn -> rdn.toAttributes().all.toList() }
            .mapNotNull { attribute ->
                val value = decodeValue(attribute.get())?.takeIf { it.isNotBlank() }
                value?.let { normalizeAttributeId(attribute.id) to it }
            }
            .toMap()

    private fun normalizeAttributeId(id: String): String {
        val name = id.removePrefix("OID.").removePrefix("oid.")
        return KEYWORD_OIDS[name.lowercase()] ?: name
    }

    /**
     * Атрибуты с нестандартными OID (ИНН, СНИЛС, должность) RFC 2253 отдаёт в виде DER-значения,
     * которое LdapName возвращает как байты или как строку "#<hex>".
     */
    private fun decodeValue(value: Any?): String? = when (value) {
        is ByteArray -> decodeDer(value)
        is String ->
            if (value.startsWith("#")) {
                runCatching { hexToBytes(value.substring(1)) }.getOrNull()?.let(::decodeDer) ?: value
            } else {
                value
            }
        else -> null
    }

    /** DER: тег (1 байт) + длина (короткая или длинная форма) + содержимое строки. */
    private fun decodeDer(der: ByteArray): String? {
        if (der.size < 2) return null
        var index = 1
        var length = der[index++].toInt() and 0xFF
        if (length and 0x80 != 0) {
            val lengthBytes = length and 0x7F
            if (lengthBytes == 0 || index + lengthBytes > der.size) return null
            length = 0
            repeat(lengthBytes) { length = (length shl 8) or (der[index++].toInt() and 0xFF) }
        }
        if (index + length > der.size) return null
        return String(der, index, length, Charsets.UTF_8)
    }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Нечётная длина hex-строки" }
        return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun emailFromSubjectAlternativeNames(certificate: X509Certificate): String? =
        runCatching {
            certificate.subjectAlternativeNames
                ?.firstOrNull { it.size >= 2 && it[0] == SAN_RFC822_NAME }
                ?.get(1) as? String
        }.getOrNull()
}
