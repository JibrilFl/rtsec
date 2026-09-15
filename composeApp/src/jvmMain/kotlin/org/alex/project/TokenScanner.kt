package org.alex.project

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class ScanSource(val title: String) {
    PKCS11("PKCS#11 (rtpkcs11ecp)"),
    CRYPTO_PRO("КриптоПро CSP (резервный режим)")
}

data class ScanResult(
    val certificates: List<CertInfo>,
    val source: ScanSource,
    val warning: String? = null
)

object TokenScanner {
    /**
     * Основной путь — прямое чтение сертификатов с носителей по PKCS#11.
     * Утилиты КриптоПро запускаются только если библиотека PKCS#11 недоступна
     * или на носителях нет объектов-сертификатов.
     */
    fun scan(): ScanResult {
        val pkcs11Result = runCatching { Pkcs11TokenScanner.scanAllTokens() }
        val certificates = pkcs11Result.getOrNull()

        if (!certificates.isNullOrEmpty()) {
            return ScanResult(certificates, ScanSource.PKCS11)
        }

        val warning = pkcs11Result.exceptionOrNull()?.let {
            "PKCS#11 недоступен (${Pkcs11TokenScanner.libraryLocation}): ${it.message}"
        } ?: "На носителях нет объектов-сертификатов PKCS#11"

        val fallback = CryptoProTokenScanner.scanAllTokens()
        return if (fallback.isEmpty() && certificates != null) {
            ScanResult(certificates, ScanSource.PKCS11, warning)
        } else {
            ScanResult(fallback, ScanSource.CRYPTO_PRO, warning)
        }
    }

    fun scanAllTokens(): List<CertInfo> = scan().certificates
}

@Composable
fun SkanToken() {
    val certs = remember { mutableStateListOf<CertInfo>() }
    val scope = rememberCoroutineScope()
    var isScanning by remember { mutableStateOf(false) }
    var scanSource by remember { mutableStateOf<ScanSource?>(null) }
    var scanWarning by remember { mutableStateOf<String?>(null) }

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

            scanWarning?.let { warning ->
                Text(
                    text = warning,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = EndfieldColors.TxtMuted,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp)
                )
            }

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
                            text = if (isScanning) {
                                "Чтение сертификатов по PKCS#11..."
                            } else {
                                "Вставьте токен и запустите сканирование"
                            },
                            fontSize = 12.sp,
                            color = EndfieldColors.TxtMuted,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                }
            } else {
                scanSource?.let { source ->
                    Text(
                        text = "ИСТОЧНИК ДАННЫХ: ${source.title}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = EndfieldColors.GoldMuted,
                        modifier = Modifier.padding(bottom = 4.dp)
                    )
                }
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
                                        Text("ЗАПИСАТЬ В БАЗУ ДАННЫХ", color = EndfieldColors.Bg0, fontWeight = FontWeight.Bold)
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
                    val result = withContext(Dispatchers.IO) {
                        TokenScanner.scan()
                    }
                    certs.addAll(result.certificates)
                    scanSource = result.source
                    scanWarning = result.warning
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
                    fontWeight = FontWeight.Bold
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
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = EndfieldColors.White,
                        textAlign = TextAlign.Center,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "STATUS: COMPLETE_WRITE",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = EndfieldColors.Gold
                    )
                }
            }
        }
    }
}
