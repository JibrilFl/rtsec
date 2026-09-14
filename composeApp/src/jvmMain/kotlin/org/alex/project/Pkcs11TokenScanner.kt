package org.alex.project

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.ptr.NativeLongByReference
import ru.rutoken.pkcs11jna.CK_ATTRIBUTE
import ru.rutoken.pkcs11jna.CK_C_INITIALIZE_ARGS
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_TOKEN
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_VALUE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKF_OS_LOCKING_OK
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKF_SERIAL_SESSION
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKR_OK
import ru.rutoken.pkcs11jna.Pkcs11Constants.CK_TRUE
import ru.rutoken.pkcs11jna.Pkcs11Constants.equalsPkcsRV
import ru.rutoken.pkcs11jna.RtPkcs11
import java.io.File

/**
 * Чтение сертификатов напрямую из токенов по PKCS#11 (библиотека rtpkcs11ecp),
 * без запуска внешних утилит КриптоПро.
 */
object Pkcs11TokenScanner {
    private const val MAX_CERTIFICATES_PER_TOKEN = 64

    /** Путь к rtpkcs11ecp задаётся системным свойством, переменной окружения или *.cfg рядом с приложением. */
    private const val LIBRARY_PROPERTY = "rutoken.pkcs11.library"
    private const val LIBRARY_ENV = "RUTOKEN_PKCS11_LIBRARY"
    private val CONFIG_FILES = listOf("rutoken.cfg", "rutoken_dynamic.cfg")

    private val pkcs11: RtPkcs11 by lazy { Native.load(libraryName(), RtPkcs11::class.java) }

    val libraryLocation: String get() = libraryName()

    fun isAvailable(): Boolean = runCatching { pkcs11 }.isSuccess

    /**
     * Возвращает по одной записи на каждый сертификат, найденный на подключённых токенах.
     * Серийный номер носителя берётся из CK_TOKEN_INFO, поэтому сертификат и железо
     * связаны однозначно, без сопоставления по фрагментам имён контейнеров.
     */
    fun scanAllTokens(): List<CertInfo> {
        val initializeArgs = CK_C_INITIALIZE_ARGS(null, null, null, null, NativeLong(CKF_OS_LOCKING_OK), null)
        checkRv("C_Initialize", pkcs11.C_Initialize(initializeArgs))
        try {
            return slotList().flatMap { slot -> scanSlot(slot) }
        } finally {
            pkcs11.C_Finalize(null)
        }
    }

    private fun scanSlot(slot: NativeLong): List<CertInfo> {
        val tokenInfo = CK_TOKEN_INFO()
        checkRv("C_GetTokenInfo", pkcs11.C_GetTokenInfo(slot, tokenInfo))
        val hardwareId = hardwareId(tokenInfo)
        val tokenLabel = String(tokenInfo.label).trim()

        val sessionPointer = NativeLongByReference()
        checkRv("C_OpenSession", pkcs11.C_OpenSession(slot, NativeLong(CKF_SERIAL_SESSION), null, null, sessionPointer))
        val session = sessionPointer.value
        try {
            return findCertificates(session).map { certificate ->
                CertificateParser.parse(
                    derCertificate = certificateValue(session, certificate),
                    hardwareId = hardwareId,
                    containerPath = tokenLabel.ifEmpty { "PKCS#11 slot ${slot.toLong()}" }
                )
            }
        } finally {
            pkcs11.C_CloseSession(session)
        }
    }

    /**
     * CK_TOKEN_INFO хранит серийный номер в шестнадцатеричном виде, а журнал ведётся
     * по десятичному номеру, напечатанному на корпусе носителя.
     */
    private fun hardwareId(tokenInfo: CK_TOKEN_INFO): String {
        val serial = String(tokenInfo.serialNumber).trim()
        return serial.toLongOrNull(16)?.toString() ?: serial
    }

    private fun slotList(): List<NativeLong> {
        val slotCount = NativeLongByReference()
        checkRv("C_GetSlotList", pkcs11.C_GetSlotList(CK_TRUE, null, slotCount))
        if (slotCount.value.toInt() == 0) return emptyList()

        val slots = Array(slotCount.value.toInt()) { NativeLong(0) }
        checkRv("C_GetSlotList", pkcs11.C_GetSlotList(CK_TRUE, slots, slotCount))
        return slots.take(slotCount.value.toInt())
    }

    @Suppress("UNCHECKED_CAST")
    private fun findCertificates(session: NativeLong): List<NativeLong> {
        val template = CK_ATTRIBUTE().toArray(2) as Array<CK_ATTRIBUTE>
        template[0].setAttr(CKA_CLASS, CKO_CERTIFICATE)
        template[1].setAttr(CKA_TOKEN, true)

        checkRv("C_FindObjectsInit", pkcs11.C_FindObjectsInit(session, template, NativeLong(template.size.toLong())))
        try {
            val found = Array(MAX_CERTIFICATES_PER_TOKEN) { NativeLong(0) }
            val foundCount = NativeLongByReference()
            checkRv("C_FindObjects", pkcs11.C_FindObjects(session, found, NativeLong(found.size.toLong()), foundCount))
            return found.take(foundCount.value.toInt())
        } finally {
            pkcs11.C_FindObjectsFinal(session)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun certificateValue(session: NativeLong, certificate: NativeLong): ByteArray {
        val template = CK_ATTRIBUTE().toArray(1) as Array<CK_ATTRIBUTE>
        template[0].setAttr(CKA_VALUE, null, 0)

        checkRv(
            "C_GetAttributeValue",
            pkcs11.C_GetAttributeValue(session, certificate, template, NativeLong(template.size.toLong()))
        )
        val length = template[0].ulValueLen.toInt()
        template[0].pValue = Memory(length.toLong())
        checkRv(
            "C_GetAttributeValue",
            pkcs11.C_GetAttributeValue(session, certificate, template, NativeLong(template.size.toLong()))
        )
        return template[0].pValue.getByteArray(0, length)
    }

    private fun libraryName(): String {
        System.getProperty(LIBRARY_PROPERTY)?.takeIf { it.isNotBlank() }?.let { return it }
        System.getenv(LIBRARY_ENV)?.takeIf { it.isNotBlank() }?.let { return it }
        libraryFromConfig()?.let { return it }
        return "rtpkcs11ecp"
    }

    /** Формат файла совпадает с конфигурацией SunPKCS11: строка `library = <путь>`. */
    private fun libraryFromConfig(): String? = CONFIG_FILES
        .map(::File)
        .firstOrNull { it.isFile }
        ?.readLines()
        ?.firstOrNull { it.trimStart().startsWith("library") }
        ?.substringAfter('=')
        ?.trim()
        ?.replace("\\\\", "\\")
        ?.takeIf { it.isNotEmpty() }

    private fun checkRv(function: String, rv: NativeLong) {
        if (!equalsPkcsRV(CKR_OK, rv)) {
            throw Pkcs11ScanException("$function failed, code 0x${java.lang.Long.toHexString(rv.toLong())}")
        }
    }
}

class Pkcs11ScanException(message: String) : RuntimeException(message)
