package org.alex.project


import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.sql.DriverManager
import java.sql.Connection
import kotlin.time.Clock
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.text.style.TextAlign
import kotlinx.datetime.*

data class CertInfo(
    val subject: String,
    val validFrom: String,
    val validTo: String,
    val mailTo: String,
    val inn: String,
    val snils: String,
    val jobTitle: String,
    val hardwareId: String = "Неизвестно",
    val containerPath: String = "Неизвестно",
    val lastNotifiedAt: String? = null // Поле подгружается из БД
)

object CertDateUtils {
    // Парсит строку формата "DD.MM.YYYY" в LocalDate
    fun parseDate(dateStr: String): LocalDate? {
        return try {
            val parts = dateStr.split(".")
            if (parts.size != 3) return null
            val day = parts[0].toInt()
            val month = parts[1].toInt()
            val year = parts[2].toInt()
            LocalDate(year, month, day)
        } catch (e: Exception) {
            null
        }
    }

    // Возвращает количество дней до окончания (отрицательное, если просрочен)
    fun getDaysRemaining(validTo: String): Int {
        val targetDate = parseDate(validTo) ?: return 0
        val today = Clock.System.now().toLocalDateTime(TimeZone.currentSystemDefault()).date
        return today.daysUntil(targetDate)
    }
}

object DatabaseManager {
    private const val DB_NAME = "crypto_journal.db"
    private const val CONNECTION_URL = "jdbc:sqlite:$DB_NAME"

    init {
        connect { conn ->
            val statement = conn.createStatement()
            val sql = """
                CREATE TABLE IF NOT EXISTS journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT,
                hardware_id TEXT,
                mail TEXT,
                valid_from TEXT,
                valid_to TEXT,
                inn TEXT,
                snils TEXT,
                jobTitle TEXT,
                container TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_notified_at TEXT,
                UNIQUE(snils, hardware_id)
                )
                """.trimIndent()

            statement.execute(sql)

            // Защита: если база уже создана без этого поля, добавляем его динамически
            try {
                statement.execute("ALTER TABLE journal ADD COLUMN last_notified_at TEXT")
            } catch (e: Exception) { /* Поле уже есть */ }
        }
    }

    private fun <T> connect(block: (Connection) -> T): T {
        val conn = DriverManager.getConnection(CONNECTION_URL)
        return try { block(conn) } finally { conn.close() }
    }

// ФУНКЦИЯ СОХРАНЕНИЯ
    fun saveToJournal(cert: CertInfo) {
        connect { conn ->

            val sql = """
                INSERT INTO journal (subject, hardware_id, mail, inn, snils, jobTitle, valid_from, valid_to, container, last_notified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, Null)
                ON CONFLICT(snils, hardware_id) DO UPDATE SET
                subject = excluded.subject,
                mail = excluded.mail,
                inn = excluded.inn,
                jobTitle = excluded.jobTitle,
                valid_from = excluded.valid_from,
                valid_to = excluded.valid_to,
                container = excluded.container,
                timestamp = CURRENT_TIMESTAMP,
                last_notified_at = NULL -- Сбрасываем в NULL при обновлении сертификата
                """.trimIndent()

            val pstmt = conn.prepareStatement(sql)
            pstmt.setString(1, cert.subject)
            pstmt.setString(2, cert.hardwareId)
            pstmt.setString(3, cert.mailTo)
            pstmt.setString(4, cert.inn)
            pstmt.setString(5, cert.snils)
            pstmt.setString(6, cert.jobTitle)
            pstmt.setString(7, cert.validFrom)
            pstmt.setString(8, cert.validTo)
            pstmt.setString(9, cert.containerPath)
            pstmt.executeUpdate()
        }
    }

    // ИСПРАВЛЕННАЯ ФУНКЦИЯ ЧТЕНИЯ (теперь читает последнее поле)
    fun getAllRecords(): List<CertInfo> {
        return connect { conn ->
            val result = mutableListOf<CertInfo>()
            val rs = conn.createStatement().executeQuery("SELECT * FROM journal ORDER BY id DESC")
            while (rs.next()) {
                result.add(
                    CertInfo(
                        subject = rs.getString("subject") ?: "",
                        hardwareId = rs.getString("hardware_id") ?: "",
                        mailTo = rs.getString("mail") ?: "",
                        validFrom = rs.getString("valid_from") ?: "",
                        validTo = rs.getString("valid_to") ?: "",
                        inn = rs.getString("inn") ?: "",
                        snils = rs.getString("snils") ?: "",
                        jobTitle = rs.getString("jobTitle") ?: "",
                        containerPath = rs.getString("container") ?: "",
                        lastNotifiedAt = rs.getString("last_notified_at") // Добавили чтение поля из БД
                    )
                )
            }
            result
        }
    }

    fun deleteRecord(snils: String, hardwareId: String) {

        connect { conn ->
            val sql = "DELETE FROM journal WHERE snils = ? AND hardware_id = ?"
            val pstmt = conn.prepareStatement(sql)
            pstmt.setString(1, snils)
            pstmt.setString(2, hardwareId)
            pstmt.executeUpdate()
        }
    }

    fun updateNotificationTime(snils: String, hardwareId: String, timeString: String) {

        connect { conn ->
            val sql = "UPDATE journal SET last_notified_at = ? WHERE snils = ? AND hardware_id = ?"
            val pstmt = conn.prepareStatement(sql)
            pstmt.setString(1, timeString)
            pstmt.setString(2, snils)
            pstmt.setString(3, hardwareId)
            pstmt.executeUpdate()
        }
    }
}

fun copyToClipboard(text: String) {
    try {
        val selection = StringSelection(text)
        Toolkit.getDefaultToolkit().systemClipboard.setContents(selection, selection)
        println("Скопировано в буфер: $text")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}

@Composable
fun Arhive() {
    var dbRecords by remember { mutableStateOf(listOf<CertInfo>()) }
    var searchQuery by remember { mutableStateOf("") } // Возвращаем поиск в UI!
    val coroutineScope = rememberCoroutineScope()

    // Фильтры и сортировка
    var filterOnlyActive by remember { mutableStateOf(false) } // Флаг фильтра "Только действующие"
    var sortByDaysRemaining by remember { mutableStateOf(false) } // Флаг сортировки по дням

    // Состояния для диалогов
    var showDeleteDialog by remember { mutableStateOf(false) }
    var recordToDelete by remember { mutableStateOf<CertInfo?>(null) }
    var showReNotifyDialog by remember { mutableStateOf(false) }
    var recordToReNotify by remember { mutableStateOf<CertInfo?>(null) }

    val blacklistedEmails = remember { listOf("admin@2okb74.ru", "alex@2okb74.ru", "aka@2okb74") }
    var expandedCardSnils by remember { mutableStateOf<String?>(null) }

    // Список для отправки уведомлений
    val selectedSnils = remember { mutableStateListOf<String>() }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            dbRecords = DatabaseManager.getAllRecords()
        }
    }

    // --- ЛОГИКА ФИЛЬТРАЦИИ И ПОИСКА ---
    val processedRecords = remember(dbRecords, searchQuery, filterOnlyActive, sortByDaysRemaining) {
        var list = dbRecords.filter {
            it.subject.contains(searchQuery, ignoreCase = true) ||
                    it.hardwareId.contains(searchQuery, ignoreCase = true) ||
                    it.jobTitle.contains(searchQuery, ignoreCase = true)
        }

        if (filterOnlyActive) {
            list = list.filter { CertDateUtils.getDaysRemaining(it.validTo) >= 0 }
        }

        list = if (sortByDaysRemaining) {
            list.sortedBy { CertDateUtils.getDaysRemaining(it.validTo) }
        } else {
            list.sortedBy { it.subject.lowercase() }
        }
        list
    }

    // [ДИАЛОГ УДАЛЕНИЯ]
    if (showDeleteDialog && recordToDelete != null) {
        AlertDialog(
            modifier = Modifier
                .background(EndfieldColors.Bg1)
                .border(1.dp, EndfieldColors.GoldBorder, CutCornerShape(0.dp))
                .padding(12.dp),
            onDismissRequest = { showDeleteDialog = false },
            containerColor = EndfieldColors.Bg1,
            title = { Text("Удаление записи", color = EndfieldColors.White) },
            text = { Column (
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Вы точно хотите удалить запись для пользователя", color = EndfieldColors.Gold)
                Text("${recordToDelete?.subject} ?", color = EndfieldColors.Teal)
                Text("Действие нельзя отменить.", color = EndfieldColors.Gold)
            } },
            confirmButton = {
                TextButton(
                    onClick = {
                        val record = recordToDelete
                        if (record != null) {
                            coroutineScope.launch(Dispatchers.IO) {
                                DatabaseManager.deleteRecord(snils = record.snils, hardwareId = record.hardwareId)
                                val updatedRecords = DatabaseManager.getAllRecords()
                                withContext(Dispatchers.Main) {
                                    dbRecords = updatedRecords
                                    showDeleteDialog = false
                                    recordToDelete = null
                                }
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.RedDim),
                    shape = CutCornerShape(bottomEnd = 6.dp)
                ) { Text("Удалить", color = EndfieldColors.Red) }
            },
            dismissButton = {
                TextButton(
                    onClick = { showDeleteDialog = false; recordToDelete = null },
                    colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.GoldDim, contentColor = EndfieldColors.Teal),
                    shape = CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp)
                ) { Text("Отмена", color = EndfieldColors.Teal) }
            }
        )
    }

    // [ДИАЛОГ ПОВТОРНОГО УВЕДОМЛЕНИЯ]
    if (showReNotifyDialog && recordToReNotify != null) {
        AlertDialog(
            onDismissRequest = { showReNotifyDialog = false },
            title = { Text("Повторное уведомление") },
            text = { Text("Пользователю ${recordToReNotify?.subject} уже отправлялось уведомление (${recordToReNotify?.lastNotifiedAt}). Отправить еще раз?") },
            confirmButton = {
                TextButton(
                    onClick = {
                        val record = recordToReNotify
                        if (record != null) {
                            coroutineScope.launch(Dispatchers.IO) {
                                EmailService.sendNotification(record.mailTo, record.subject, record.validTo)
                                val nowTime = Clock.System.now().toString().substringBefore("T")
                                DatabaseManager.updateNotificationTime(record.snils, record.hardwareId, nowTime)
                                val updated = DatabaseManager.getAllRecords()
                                withContext(Dispatchers.Main) { dbRecords = updated }
                            }
                        }
                        showReNotifyDialog = false
                        recordToReNotify = null
                    }
                ) { Text("Отправить заново") }
            },
            dismissButton = {
                TextButton(onClick = { showReNotifyDialog = false; recordToReNotify = null }) { Text("Отмена") }
            }
        )
    }

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Top
    ) {

        // --- ПАНЕЛЬ ПОИСКА И УПРАВЛЕНИЯ ФИЛЬТРАМИ (Вернули и расширили) ---
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Текстовый поисковик
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Поиск по ФИО, должности или ID токена...", color = EndfieldColors.TxtMuted) },
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = EndfieldColors.Gold,
                    unfocusedBorderColor = EndfieldColors.GoldBorder,
                    focusedTextColor = EndfieldColors.White,
                    unfocusedTextColor = EndfieldColors.Txt
                ),
                shape = CutCornerShape(0.dp)
            )

            // Кнопка-переключатель: Только активные КЭП
            Button(
                onClick = { filterOnlyActive = !filterOnlyActive },
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (filterOnlyActive) EndfieldColors.GoldDim else EndfieldColors.Bg0,
                    contentColor = if (filterOnlyActive) EndfieldColors.Gold else EndfieldColors.TxtMuted
                ),
                shape = CutCornerShape(0.dp),
                modifier = Modifier.height(56.dp).border(1.dp, if (filterOnlyActive) EndfieldColors.Gold else EndfieldColors.GoldBorder, CutCornerShape(0.dp))
            ) {
                Text(if (filterOnlyActive) "● ДЕЙСТВУЮЩИЕ" else "○ ВСЕ СРОКИ", fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }

            // Кнопка-переключатель: Сортировка по дням
            Button(
                onClick = { sortByDaysRemaining = !sortByDaysRemaining },
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (sortByDaysRemaining) EndfieldColors.GoldDim else EndfieldColors.Bg0,
                    contentColor = if (sortByDaysRemaining) EndfieldColors.Gold else EndfieldColors.TxtMuted
                ),
                shape = CutCornerShape(0.dp),
                modifier = Modifier.height(56.dp).border(1.dp, if (sortByDaysRemaining) EndfieldColors.Gold else EndfieldColors.GoldBorder, CutCornerShape(0.dp))
            ) {
                Text(if (sortByDaysRemaining) "▼ ПО СРОКУ ИСТ КЭП" else "⇅ ПО АЛФАВИТУ", fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
        }

        // --- ШАПКА ТАБЛИЦЫ ---
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(EndfieldColors.Bg0)
                .padding(horizontal = 16.2.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text("ВЛАДЕЛЕЦ КЭП / ПОЧТА", modifier = Modifier.weight(1.93f), fontSize = 11.sp, color = EndfieldColors.TxtMuted, fontFamily = FontFamily.Monospace)
            Text("ИСТЕКАЕТ", modifier = Modifier.weight(1f), fontSize = 11.sp, color = EndfieldColors.TxtMuted, fontFamily = FontFamily.Monospace)
            Text("ОСТАЛОСЬ ДНЕЙ", modifier = Modifier.weight(1f), fontSize = 11.sp, color = EndfieldColors.TxtMuted, fontFamily = FontFamily.Monospace)
        }

        if (processedRecords.isEmpty()) {
            Text("Записей не найдено", modifier = Modifier.padding(16.dp), color = Color.Gray)
        } else {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(processedRecords) { record ->
                    val isExpanded = expandedCardSnils == record.snils
                    val daysLeft = CertDateUtils.getDaysRemaining(record.validTo)
                    val isExpired = daysLeft < 0

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp)
                            .clickable { expandedCardSnils = if (isExpanded) null else record.snils }
                            .border(1.dp, EndfieldColors.GoldBorder, CutCornerShape(0.dp)),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isExpanded) EndfieldColors.Bg2 else EndfieldColors.Bg0
                        ),
                        shape = CutCornerShape(0.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {

                            // --- СТРОКА ТАБЛИЦЫ ---
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                // Чекбокс
                                val isChecked = selectedSnils.contains(record.snils)
                                androidx.compose.material3.Checkbox(
                                    checked = isChecked,
                                    onCheckedChange = { checked ->
                                        if (checked) {
                                            selectedSnils.add(record.snils)
                                        } else {
                                            selectedSnils.remove(record.snils)
                                        }
                                    },
                                    colors = androidx.compose.material3.CheckboxDefaults.colors(
                                        checkedColor = EndfieldColors.Gold,
                                        uncheckedColor = EndfieldColors.GoldBorder,
                                        checkmarkColor = EndfieldColors.Bg0
                                    ),
                                    modifier = Modifier.padding(end = 8.dp)
                                )

                                // Колонка 1: Субъект и почта
                                Column(modifier = Modifier.weight(1.8f)) {
                                    Text(
                                        text = record.subject,
                                        color = EndfieldColors.White,
                                        style = MaterialTheme.typography.titleMedium,
                                        modifier = Modifier.clickable { copyToClipboard(record.subject) }
                                    )
                                    Text(record.mailTo, color = EndfieldColors.GoldMuted, style = MaterialTheme.typography.bodySmall)
                                }

                                // Колонка 2: Срок действия
                                Text(
                                    text = record.validTo,
                                    modifier = Modifier.weight(1f),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = EndfieldColors.White
                                )

                                // Колонка 3: Счетчик оставшихся дней
                                Text(
                                    text = if (isExpired) { "ИСТЕКЛО" } else { "$daysLeft дн." },
                                    modifier = Modifier.weight(1f),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = when {
                                        isExpired -> EndfieldColors.Red
                                        daysLeft <= 30 -> Color(0xFFE87030) // Оранжевый — критически мало дней
                                        else -> EndfieldColors.Teal // Бирюзовый — все отлично
                                    }
                                )
                            }

                            // --- ВЛОЖЕННЫЙ БЛОК ДЕТАЛЕЙ (По клику) ---
                            if (isExpanded) {
                                Spacer(modifier = Modifier.height(12.dp))
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(EndfieldColors.Bg1)
                                        .border(1.dp, EndfieldColors.GoldBorder, CutCornerShape(0.dp))
                                        .padding(12.dp)
                                ) {
                                    Text("Должность: ${record.jobTitle}", color = EndfieldColors.White, style = MaterialTheme.typography.bodySmall)
                                    Text("Токен: ${if (record.hardwareId == "ID не найден") "" else record.hardwareId}", color = EndfieldColors.Gold, style = MaterialTheme.typography.bodySmall)
                                    Text("Выдан: ${record.validFrom}", color = EndfieldColors.TxtMuted, style = MaterialTheme.typography.bodySmall)

                                    Spacer(modifier = Modifier.height(6.dp))

                                    // Кликабельный ИНН
                                    Text(
                                        text = "ИНН: ${record.inn}",
                                        color = EndfieldColors.Txt,
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.clickable { copyToClipboard(record.inn) }.padding(vertical = 2.dp)
                                    )

                                    // Кликабельный СНИЛС
                                    Text(
                                        text = "СНИЛС: ${record.snils}",
                                        color = EndfieldColors.Txt,
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.clickable { copyToClipboard(record.snils) }.padding(vertical = 2.dp)
                                    )

                                    if (record.lastNotifiedAt != null) {
                                        Text("🖂 Последнее письмо отправлено: ${record.lastNotifiedAt}", color = EndfieldColors.Gold, style = MaterialTheme.typography.bodySmall)
                                    }
                                }

                                // Кнопки действий под спойлером
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Button(
                                        onClick = {
                                            val email = record.mailTo
                                            if (email.isNullOrBlank()) return@Button
                                            if (blacklistedEmails.contains(email.lowercase().trim())) return@Button

                                            if (record.lastNotifiedAt != null) {
                                                recordToReNotify = record
                                                showReNotifyDialog = true
                                            } else {
                                                coroutineScope.launch(Dispatchers.IO) {
                                                    EmailService.sendNotification(email, record.subject, record.validTo)
                                                    val nowTime = Clock.System.now().toString().substringBefore("T")
                                                    DatabaseManager.updateNotificationTime(record.snils, record.hardwareId, nowTime)
                                                    val updated = DatabaseManager.getAllRecords()
                                                    withContext(Dispatchers.Main) { dbRecords = updated }
                                                }
                                            }
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.GoldDim, contentColor = EndfieldColors.Teal),
                                        shape = CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp),
                                        modifier = Modifier.border(1.dp, EndfieldColors.Teal, CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp))
                                    ) {
                                        Text(if (record.lastNotifiedAt != null) "Отправить снова" else "Уведомить")
                                    }

                                    Spacer(modifier = Modifier.width(4.dp))

                                    Button(
                                        onClick = {
                                            recordToDelete = record
                                            showDeleteDialog = true
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.RedDim, contentColor = EndfieldColors.Red),
                                        shape = CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp),
                                        modifier = Modifier.border(1.dp, EndfieldColors.Red, CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp))
                                    ) {
                                        Text("Удалить")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- НИЖНЯЯ ПАНЕЛЬ МАССОВЫХ ДЕЙСТВИЙ ---
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Кнопка обновления списка всегда слева
            Button(
                onClick = {
                    coroutineScope.launch(Dispatchers.IO) {
                        dbRecords = DatabaseManager.getAllRecords()
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.Steel),
                shape = CutCornerShape(0.dp)
            ) {
                Text("Обновить список", color = EndfieldColors.White)
            }

            // Кнопка появляется ТОЛЬКО если проставлены чекбоксы
            if (selectedSnils.isNotEmpty()) {
                Button(
                    onClick = {
                        coroutineScope.launch(Dispatchers.IO) {
                            // Отправляем письма ИСКЛЮЧИТЕЛЬНО отмеченным
                            dbRecords.filter { selectedSnils.contains(it.snils) }.forEach { record ->
                                val email = record.mailTo
                                if (!email.isNullOrBlank() && !blacklistedEmails.contains(email.lowercase().trim())) {
                                    try {
                                        EmailService.sendNotification(email, record.subject, record.validTo)
                                        val nowTime = Clock.System.now().toString().substringBefore("T")
                                        DatabaseManager.updateNotificationTime(record.snils, record.hardwareId, nowTime)
                                    } catch (e: Exception) { e.printStackTrace() }
                                }
                            }
                            // После отправки послушно тушим все галочки, и кнопка сама исчезнет
                            withContext(Dispatchers.Main) { selectedSnils.clear() }
                            dbRecords = DatabaseManager.getAllRecords()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.Teal),
                    shape = CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp),
                    modifier = Modifier.border(1.dp, EndfieldColors.Teal, CutCornerShape(topStart = 0.dp, bottomEnd = 8.dp))
                ) {
                    Text(
                        text = "УВЕДОМИТЬ ОТМЕЧЕННЫХ (${selectedSnils.size})",
                        color = EndfieldColors.Bg0,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                }
            }
        }
    }
}