package org.alex.project


import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.time.Clock
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import javax.naming.ldap.LdapName


object TokenScanner {
    fun scanAllTokens(): List<CertInfo> {

        val resultList = mutableListOf<CertInfo>()

        // Теперь получаем LIST пар, где порядок строго сохранен!
        val hardwareFuture = getHardwareSerials()

        try {
            val containers = ProcessBuilder(
                "C:\\Program Files\\Crypto Pro\\CSP\\csptest.exe",
                "-keyset", "-enum_cont", "-verifycontext", "-fqcn", "-machine"
            ).start().inputStream.bufferedReader(charset("CP866")).readLines()
                .filter { it.contains("\\\\.\\") }
                .map { it.trim() }


            // Создаем изменяемую копию списка, чтобы "вычеркивать" использованные серийники
            val remainingHardware = hardwareFuture.toMutableList()

            if (containers.isNotEmpty()) {
                containers.forEach { path ->
                    val readerName = path.substringAfter("\\\\.\\").substringBefore("\\").trim()
                    // Универсальное извлечение ID контейнера из пути
                    // Берем только имя контейнера (последнюю часть пути после слэша)
                    val containerName = path.substringAfterLast("\\").trim()

                    // Ищем сплошной кусок цифр длиной от 9 до 13 знаков в любом месте строки.
                    // Если вдруг такого длинного числа нет, берем вообще любые первые попавшиеся цифры.
                    val code = """\d{9,13}""".toRegex().find(containerName)?.value
                        ?: """\d+""".toRegex().find(containerName)?.value
                        ?: readerName // крайний случай, если цифр вообще нет

                    // УМНЫЙ ПОИСК СЕРИЙНИКА:
                    // Ищем в списке железа первую подходящую запись

                    val matchIndex = remainingHardware.indexOfFirst { pair ->
                        pair.first.contains(code, true) || code.contains(pair.first, true)
                    }

                    val realSerial = if (matchIndex != -1) {
                        remainingHardware.removeAt(matchIndex).second
                    } else if (remainingHardware.isNotEmpty()) {
                        remainingHardware.removeAt(0).second
                    } else {
                        "ID не найден"
                    }

                    val info = fetchInfoDirectly(path)

                    resultList.add(
                        CertInfo(
                            subject = info.subject,
                            validFrom = info.validFrom,
                            validTo = info.validTo,
                            mailTo = info.mailTo,
                            inn = info.inn,
                            snils = info.snils,
                            jobTitle = info.jobTitle,
                            hardwareId = realSerial,
                            containerPath = path
                        )

                    )

                }

            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return resultList
    }
    fun getHardwareSerials(): List<Pair<String, String>> {
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
            process.inputStream.bufferedReader(charset("CP866")).useLines { lines ->
                var lastId = ""
                lines.forEach { line ->
                    val trimmedLine = line.trim()

                    // Пытаемся вытащить ID из текущей строки
                    val foundId = extractKeyIds(trimmedLine).firstOrNull()
                    if (foundId != null) {
                        lastId = foundId
                    }

                    if (line.contains("SCARD\\")) {
                        regex.find(line)?.groupValues?.get(1)?.let { hex ->
                            val code = hex.toLong(16).toString()
                            if (lastId.isNotEmpty()) {
                            // Добавляем в список как пару (Контейнер -> Железо)
                                list.add(Pair(lastId, code))
                                lastId = "" // Очищаем для следующего токена
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
    fun fetchInfoDirectly(path: String): CertInfo {
        var subject = "Неизвестно"
        var validFrom = "Неизвестно"
        var validTo = "Неизвестно"
        var mailTo = "Неизвестно"
        var inn = "Неизвестно"
        var snils = "Неизвестно"
        var jobTitle = "Неизвестно"

        try {
            val process =
                ProcessBuilder("C:\\Program Files\\Crypto Pro\\CSP\\certmgr.exe", "-list", "-container", path).start()
            process.inputStream.bufferedReader(charset("CP866")).useLines { lines ->
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
                        val rawDateTime = l.substringAfter(":").substringBefore("UTC").trim()
                        validFrom = rawDateTime.substringBefore(" ").replace("/", ".")
                    }

                    if (l.startsWith("Истекает")) {
                        val rawDateTime = l.substringAfter(":").substringBefore("UTC").trim()
                        validTo = rawDateTime.substringBefore(" ").replace("/", ".")
                    }
                }
            }
        } catch (e: Exception) {
        }

        return CertInfo(subject, validFrom, validTo, mailTo, inn, snils, jobTitle)
    }
    fun extractKeyIds(input: String): List<String> {
        val regex = Regex("""\d{8,13}""")
        return regex.findAll(input).map { it.value }.distinct().toList()
    }
}

@Composable
fun SkanToken() {
    val certs = remember { mutableStateListOf<CertInfo>() }
    val scope = rememberCoroutineScope()
    var isScanning by remember { mutableStateOf(false) }

    // Состояние для всплывающего уведомления
    var successMessage by remember { mutableStateOf<String?>(null) }

    // Анимация пульсации для заглушки (эффект сканирования/ожидания)
    val infiniteTransition = rememberInfiniteTransition()
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        )
    )

    // Обертка в Box, чтобы зафиксировать кнопку в углу экрана
    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Top
        ) {

            if (certs.isEmpty()) {
                // --- ЗАГЛУШКА С АНИМАЦИЕЙ ---
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .background(EndfieldColors.Bg0)
                        .border(1.dp, EndfieldColors.GoldBorder),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        // Пульсирующий индикатор
                        Box(
                            modifier = Modifier
                                .size(12.dp)
                                .alpha(pulseAlpha)
                                .background(EndfieldColors.Gold, CutCornerShape(50))
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = if (isScanning) "ВЫПОЛНЯЕТСЯ ОПРОС УСТРОЙСТВ..." else "НОСИТЕЛИ НЕ ОБНАРУЖЕНЫ",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.sp,
                            color = if (isScanning) EndfieldColors.Gold else EndfieldColors.TxtMuted,
                            letterSpacing = 1.5.sp
                        )
                        Text(
                            text = if (isScanning) "Парсинг вывода КриптоПро CSP..." else "Вставьте токен и запустите сканирование",
                            fontSize = 12.sp,
                            color = EndfieldColors.TxtMuted,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                }
            } else {
                // --- СПИСОК НАЙДЕННЫХ ТОКЕНОВ ---
                LazyColumn(modifier = Modifier.weight(1f)) {
                    items(certs) { cert ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .border(1.dp, EndfieldColors.GoldBorder, CutCornerShape(0.dp)),
                            colors = CardDefaults.cardColors(
                                containerColor = EndfieldColors.Bg0
                            ),
                            shape = CutCornerShape(0.dp)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Row(verticalAlignment = Alignment.Top) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(cert.subject, style = MaterialTheme.typography.titleMedium, color = EndfieldColors.White)
                                        Row {
                                            Text("ID: ", style = MaterialTheme.typography.bodySmall, color = EndfieldColors.White)
                                            Text(cert.hardwareId, style = MaterialTheme.typography.bodySmall, color = EndfieldColors.Gold)
                                        }
                                        Row {
                                            Text("Действует до: ", style = MaterialTheme.typography.bodySmall, color = EndfieldColors.White)
                                            Text(cert.validTo, style = MaterialTheme.typography.bodySmall, color = EndfieldColors.Gold)
                                        }
                                    }
                                    Button(
                                        onClick = {
                                            DatabaseManager.saveToJournal(cert)
                                            println("Запись сохранена: ${cert.subject}")
                                            scope.launch {
                                                successMessage = "ДАННЫЕ СИНХРОНИЗИРОВАНЫ \n // ${cert.subject.uppercase()} \\\\"
                                                kotlinx.coroutines.delay(2000) // Ждем ровно 2 секунды
                                                successMessage = null // Скрываем окно
                                            }
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.Gold),
                                        shape = CutCornerShape(bottomEnd = 6.dp)
                                    ) {
                                        Text("ЗАПИСАТЬ В БАЗУ ДАННЫХ", color = EndfieldColors.Bg0, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- КНОПКА СКАНИРОВАНИЯ В ПРАВОМ НИЖНЕМ УГЛУ ---
        Button(
            onClick = {
                scope.launch {
                    isScanning = true
                    certs.clear()
                    val found = withContext(Dispatchers.IO) {
                        TokenScanner.scanAllTokens()
                    }
                    certs.addAll(found)
                    isScanning = false
                }
            },
            enabled = !isScanning,
            modifier = Modifier
                .align(Alignment.BottomEnd) // Позиционируем в правый нижний угол
                .padding(bottom = 16.dp, end = 16.dp)
                .height(48.dp)
                .border(1.dp, EndfieldColors.Gold, CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp)),
            colors = ButtonDefaults.buttonColors(
                containerColor = EndfieldColors.GoldDim,
                contentColor = EndfieldColors.Gold,
                disabledContainerColor = EndfieldColors.Bg0,
                disabledContentColor = EndfieldColors.TxtMuted
            ),
            shape = CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (isScanning) {
                    // Оборачиваем в Box с фиксированным размером, чтобы зафиксировать центр вращения
                    Box(
                        modifier = Modifier
                            .padding(end = 8.dp)
                            .size(18.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.fillMaxSize(), // Занимает строго пространство Box 18x18
                            color = EndfieldColors.Gold,
                            strokeWidth = 2.dp
                        )
                    }
                }
                Text(
                    text = if (isScanning) "СКАНИРОВАНИЕ..." else "ЗАПУСТИТЬ СКАНИРОВАНИЕ",
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.Bold
                )
            }
        }

        // МОДАЛЬНОЕ ОКНО УВЕДОМЛЕНИЯ
        if (successMessage != null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color(0x99000000)) // Полупрозрачный черный фон на весь экран, чтобы затенить задник
                    .clickable(enabled = false) {}, // Блокируем клики по элементам сзади, пока горит окно
                contentAlignment = Alignment.Center
            ) {
                // Само окошко в стиле Endfield
                Column(
                    modifier = Modifier
                        .width(400.dp)
                        .background(EndfieldColors.Bg0)
                        .border(1.dp, EndfieldColors.Gold, CutCornerShape(0.dp))
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Маленький технологичный маркер успеха (зеленый или золотой)
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(EndfieldColors.Teal, CutCornerShape(50))
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = successMessage ?: "",
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = EndfieldColors.White,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "STATUS: COMPLETE_WRITE",
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = EndfieldColors.Gold
                    )
                }
            }
        }
    }
}