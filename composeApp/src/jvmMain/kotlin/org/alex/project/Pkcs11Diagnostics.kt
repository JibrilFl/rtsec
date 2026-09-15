package org.alex.project

import com.sun.jna.Memory
import com.sun.jna.NativeLong
import com.sun.jna.ptr.NativeLongByReference
import ru.rutoken.pkcs11jna.CK_ATTRIBUTE
import ru.rutoken.pkcs11jna.CK_C_INITIALIZE_ARGS
import ru.rutoken.pkcs11jna.CK_SLOT_INFO
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_APPLICATION
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_TYPE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_LABEL
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_PRIVATE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_VALUE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKF_OS_LOCKING_OK
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKF_SERIAL_SESSION
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_DATA
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PRIVATE_KEY
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PUBLIC_KEY
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_SECRET_KEY
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKU_USER
import java.io.File

/**
 * Отчёт о содержимом подключённых токенов: слоты, CK_TOKEN_INFO и все объекты PKCS#11
 * с их классом, меткой и размером значения. Нужен, чтобы понять, в каком виде носитель
 * отдаёт сертификаты, когда штатное сканирование их не находит.
 *
 * Запуск: ./gradlew :composeApp:pkcs11Diagnostics
 */
object Pkcs11Diagnostics {
    private const val MAX_OBJECTS = 512

    private val CLASS_NAMES = mapOf(
        CKO_DATA to "CKO_DATA",
        CKO_CERTIFICATE to "CKO_CERTIFICATE",
        CKO_PUBLIC_KEY to "CKO_PUBLIC_KEY",
        CKO_PRIVATE_KEY to "CKO_PRIVATE_KEY",
        CKO_SECRET_KEY to "CKO_SECRET_KEY"
    )

    private val pkcs11 get() = Pkcs11TokenScanner.pkcs11

    fun report(pin: CharArray?): String = buildString {
        appendLine("Библиотека PKCS#11: ${Pkcs11TokenScanner.libraryLocation}")
        val args = CK_C_INITIALIZE_ARGS(null, null, null, null, NativeLong(CKF_OS_LOCKING_OK), null)
        Pkcs11TokenScanner.checkRv("C_Initialize", pkcs11.C_Initialize(args))
        try {
            val slots = Pkcs11TokenScanner.slotList()
            appendLine("Слотов с носителями: ${slots.size}")
            slots.forEach { slot -> appendSlot(slot, pin) }
        } finally {
            pkcs11.C_Finalize(null)
        }
    }

    private fun StringBuilder.appendSlot(slot: NativeLong, pin: CharArray?) {
        appendLine()
        appendLine("=== Слот ${slot.toLong()} ===")
        val slotInfo = CK_SLOT_INFO()
        if (isOk(pkcs11.C_GetSlotInfo(slot, slotInfo))) {
            appendLine("Считыватель: ${text(slotInfo.slotDescription)}")
        }
        val tokenInfo = CK_TOKEN_INFO()
        Pkcs11TokenScanner.checkRv("C_GetTokenInfo", pkcs11.C_GetTokenInfo(slot, tokenInfo))
        appendLine("Метка: ${text(tokenInfo.label)}")
        appendLine("Модель: ${text(tokenInfo.model)}")
        appendLine("Производитель: ${text(tokenInfo.manufacturerID)}")
        appendLine("Серийный номер: ${text(tokenInfo.serialNumber)}")
        appendLine("Флаги: 0x${java.lang.Long.toHexString(tokenInfo.flags.toLong())}")
        appendLine("Прошивка: ${tokenInfo.firmwareVersion.major}.${tokenInfo.firmwareVersion.minor}")

        val sessionPointer = NativeLongByReference()
        Pkcs11TokenScanner.checkRv(
            "C_OpenSession",
            pkcs11.C_OpenSession(slot, NativeLong(CKF_SERIAL_SESSION), null, null, sessionPointer)
        )
        val session = sessionPointer.value
        try {
            appendLine("-- объекты без авторизации --")
            appendObjects(session)
            if (pin == null) {
                appendLine("-- PIN не вводился, приватные объекты не видны --")
                return
            }
            val pinBytes = String(pin).toByteArray()
            val rv = pkcs11.C_Login(session, NativeLong(CKU_USER), pinBytes, NativeLong(pinBytes.size.toLong()))
            pinBytes.fill(0)
            if (!isOk(rv)) {
                appendLine("-- C_Login не удался, код 0x${java.lang.Long.toHexString(rv.toLong())} --")
                return
            }
            appendLine("-- объекты после ввода PIN --")
            appendObjects(session)
            pkcs11.C_Logout(session)
        } finally {
            pkcs11.C_CloseSession(session)
        }
    }

    private fun StringBuilder.appendObjects(session: NativeLong) {
        val objects = findAllObjects(session)
        appendLine("Найдено объектов: ${objects.size}")
        objects.forEachIndexed { index, handle ->
            val objectClass = longAttribute(session, handle, CKA_CLASS)
            val className = objectClass?.let { CLASS_NAMES[it] ?: "0x${java.lang.Long.toHexString(it)}" } ?: "?"
            val label = stringAttribute(session, handle, CKA_LABEL)
            val application = stringAttribute(session, handle, CKA_APPLICATION)
            val id = byteAttribute(session, handle, CKA_ID)?.let(::hex)
            val valueLength = attributeLength(session, handle, CKA_VALUE)
            val certificateType = longAttribute(session, handle, CKA_CERTIFICATE_TYPE)
            val private = longAttribute(session, handle, CKA_PRIVATE)
            appendLine(
                "[$index] class=$className private=$private label=${label ?: "-"} " +
                    "application=${application ?: "-"} id=${id ?: "-"} " +
                    "CKA_VALUE=${valueLength ?: "нет"} certType=${certificateType ?: "-"}"
            )
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun findAllObjects(session: NativeLong): List<NativeLong> {
        Pkcs11TokenScanner.checkRv("C_FindObjectsInit", pkcs11.C_FindObjectsInit(session, null, NativeLong(0)))
        try {
            val found = Array(MAX_OBJECTS) { NativeLong(0) }
            val foundCount = NativeLongByReference()
            Pkcs11TokenScanner.checkRv(
                "C_FindObjects",
                pkcs11.C_FindObjects(session, found, NativeLong(found.size.toLong()), foundCount)
            )
            return found.take(foundCount.value.toInt())
        } finally {
            pkcs11.C_FindObjectsFinal(session)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun attributeLength(session: NativeLong, handle: NativeLong, type: Long): Int? {
        val template = CK_ATTRIBUTE().toArray(1) as Array<CK_ATTRIBUTE>
        template[0].setAttr(type, null, 0)
        if (!isOk(pkcs11.C_GetAttributeValue(session, handle, template, NativeLong(1)))) return null
        return template[0].ulValueLen.toInt().takeIf { it >= 0 }
    }

    @Suppress("UNCHECKED_CAST")
    private fun byteAttribute(session: NativeLong, handle: NativeLong, type: Long): ByteArray? {
        val length = attributeLength(session, handle, type)?.takeIf { it > 0 } ?: return null
        val template = CK_ATTRIBUTE().toArray(1) as Array<CK_ATTRIBUTE>
        template[0].setAttr(type, Memory(length.toLong()), length.toLong())
        if (!isOk(pkcs11.C_GetAttributeValue(session, handle, template, NativeLong(1)))) return null
        return template[0].pValue.getByteArray(0, length)
    }

    private fun longAttribute(session: NativeLong, handle: NativeLong, type: Long): Long? =
        byteAttribute(session, handle, type)?.let { bytes ->
            bytes.foldIndexed(0L) { index, acc, byte -> acc or ((byte.toLong() and 0xFF) shl (8 * index)) }
        }

    private fun stringAttribute(session: NativeLong, handle: NativeLong, type: Long): String? =
        byteAttribute(session, handle, type)?.toString(Charsets.UTF_8)?.trim()?.takeIf { it.isNotEmpty() }

    private fun text(raw: ByteArray) = String(raw, Charsets.UTF_8).trim()

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02X".format(it) }

    private fun isOk(rv: NativeLong) =
        runCatching { Pkcs11TokenScanner.checkRv("", rv) }.isSuccess
}

fun main() {
    val console = System.console()
    print("PIN пользователя (Enter — пропустить, приватные объекты не будут видны): ")
    System.out.flush()
    val pin = console?.readPassword() ?: readlnOrNull()?.toCharArray()
    val report = runCatching { Pkcs11Diagnostics.report(pin?.takeIf { it.isNotEmpty() }) }
        .getOrElse { "Ошибка: ${it.message}" }
    pin?.fill('\u0000')
    println(report)
    val file = File("pkcs11-report.txt")
    file.writeText(report)
    println("Отчёт сохранён: ${file.absolutePath}")
}
