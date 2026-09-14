package org.alex.project

import androidx.compose.foundation.HorizontalScrollbar
import androidx.compose.foundation.VerticalScrollbar
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.snapping.SnapPosition
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.apache.poi.xssf.usermodel.XSSFWorkbook
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Properties

// Модель строки журнала (15 колонок согласно твоей шапке)
data class JournalRow(
    val id: String,          // 1. № п/п
    val nameSKZI: String,    // 2. Наименование СКЗИ
    val serialSKZI: String,  // 3. Серийные номера СКЗИ
    val keyNumbers: String,  // 4. Номера экземпляров ключевых документов
    val receivedFrom: String,// 5. От кого получены
    val receivedDoc: String, // 6. Дата и номер сопроводительного письма
    val userFio: String,     // 7. Ф.И.О. пользователя СКЗИ
    val receivedDate: String,// 8. Дата и расписка в получении
    val installerFio: String,// 9. Ф.И.О. сотрудника, производившего установку
    val installDate: String, // 10. Дата подключения и подпись
    val hardwareInfo: String,// 11. Номера аппаратных средств, куда установлено СКЗИ
    val removeDate: String,  // 12. Дата изъятия
    val removerFio: String,  // 13. Ф.И.О. сотрудника, производившего изъятие
    val destructionDoc: String,// 14. Номер акта об уничтожении
    val comment: String      // 15. Примечание
)

object ExcelJournalManager {

    private val CONFIG_FILE_PATH = "skzi_config.properties"
    var EXCEL_FILE_PATH = "skzi.xlsx"
    var defaultSkziName = "РУТОКЕН"
    var defaultInstaller = "Администратор"


    init {
        loadSettings()
    }

    fun saveSettings() {
        try {
            val props = Properties()
            props.setProperty("excel_path", EXCEL_FILE_PATH)
            props.setProperty("skzi_name", defaultSkziName)
            props.setProperty("defaultInstaller", defaultInstaller)

            FileOutputStream(CONFIG_FILE_PATH).use { fos ->
                props.store(fos, "Journal Configuration")
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun loadSettings() {
        val file = File(CONFIG_FILE_PATH)
        if (!file.exists()) return // Если файла нет, остаются дефолтные значения из кода

        try {
            val props = Properties()
            FileInputStream(file).use { fis ->
                props.load(fis)
            }
            // Читаем значения из файла, если какого-то ключа нет — берем дефолт
            EXCEL_FILE_PATH = props.getProperty("excel_path", EXCEL_FILE_PATH)
            defaultSkziName = props.getProperty("skzi_name", defaultSkziName)
            defaultInstaller = props.getProperty("defaultInstaller", defaultInstaller)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun readJournal(): List<JournalRow> {
        val file = File(EXCEL_FILE_PATH)
        if (!file.exists()) return emptyList()

        val list = mutableListOf<JournalRow>()
        try {
            FileInputStream(file).use { fis ->
                val workbook = XSSFWorkbook(fis)
                val sheet = workbook.getSheetAt(0)

                // Данные начинаются со строки индекса 4 (5-я строка в Excel, после шапки)
                val startRowIndex = 2

                for (i in startRowIndex..sheet.lastRowNum) {
                    val row = sheet.getRow(i) ?: continue

                    // Если первая ячейка (№ п/п) пустая — значит журнал закончился
                    val id = row.getCell(0)?.toString()?.substringBefore(".") ?: ""
                    if (id.isBlank()) continue

                    list.add(
                        JournalRow(
                            id = id,
                            nameSKZI = row.getCell(1)?.toString() ?: "",
                            serialSKZI = row.getCell(2)?.toString() ?: "",
                            keyNumbers = row.getCell(3)?.toString() ?: "",
                            receivedFrom = row.getCell(4)?.toString() ?: "",
                            receivedDoc = row.getCell(5)?.toString() ?: "",
                            userFio = row.getCell(6)?.toString() ?: "",
                            receivedDate = row.getCell(7)?.toString() ?: "",
                            installerFio = row.getCell(8)?.toString() ?: "",
                            installDate = row.getCell(9)?.toString() ?: "",
                            hardwareInfo = row.getCell(10)?.toString() ?: "",
                            removeDate = row.getCell(11)?.toString() ?: "",
                            removerFio = row.getCell(12)?.toString() ?: "",
                            destructionDoc = row.getCell(13)?.toString() ?: "",
                            comment = row.getCell(14)?.toString() ?: ""
                        )
                    )
                }
                workbook.close()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return list
    }

    /**
     * Дописывает новую запись в конец Excel файла
     */
    fun appendRow(newRow: JournalRow) {
        val file = File(EXCEL_FILE_PATH)
        if (!file.exists()) return

        try {
            val fis = FileInputStream(file)
            val workbook = XSSFWorkbook(fis)
            val sheet = workbook.getSheetAt(0)
            fis.close()

            // Находим реальную последнюю заполненную гостовскую строку, проверяя ячейку № п/п
            var lastFilledRowIndex = 1 // Шапка заканчивается на 2 индексе
            for (i in 2..sheet.lastRowNum) {
                val r = sheet.getRow(i)
                val idCell = r?.getCell(0)?.toString() ?: ""
                if (idCell.isNotBlank()) {
                    lastFilledRowIndex = i
                }
            }

            // Вычисляем № п/п на основе предыдущей записи
            val prevNum = sheet.getRow(lastFilledRowIndex)?.getCell(0)?.toString()?.substringBefore(".")?.toIntOrNull() ?: 0
            val currentNum = prevNum + 1

            // Создаем новую строку СРАЗУ за последней заполненной
            val nextRowIndex = lastFilledRowIndex + 1
            val row = sheet.getRow(nextRowIndex) ?: sheet.createRow(nextRowIndex)

            // =========================================================================
            // 📑 КАРТА ЗАПОЛНЕНИЯ КОЛОНОК EXCEL
            // =========================================================================

            // Колонка 1: № п/п
            row.createCell(0).setCellValue(currentNum.toDouble())

            // Колонка 2: Наименование СКЗИ и техно-документации
            row.createCell(1).setCellValue(newRow.nameSKZI.ifBlank { defaultSkziName })

            // Колонка 3: Серийный номер токена/флешки (наш hardwareId)
            row.createCell(2).setCellValue(newRow.serialSKZI)

            // Колонка 4: Номера экземпляров (Имя контейнера КриптоПро)
            row.createCell(3).setCellValue(newRow.keyNumbers)

            // Колонка 5: От кого получены
            row.createCell(4).setCellValue(newRow.receivedFrom.ifBlank { defaultInstaller })

            // Колонка 6: Дата и номер сопроводительного письма
            row.createCell(5).setCellValue(newRow.receivedDoc)

            // Колонка 7: Ф.И.О. сотрудника, которому выдали КЭП
            row.createCell(6).setCellValue(newRow.userFio)

            // Колонка 8: Дата и расписка в получении
            row.createCell(7).setCellValue(newRow.receivedDate)

            // Колонка 9: Кто ставил СКЗИ (например, Администратор ИБ)
            row.createCell(8).setCellValue(newRow.installerFio.ifBlank { defaultInstaller })

            // Колонка 10: Дата подключения/установки
            row.createCell(9).setCellValue(newRow.installDate)

            // Колонка 11: Имя компа / инвентарник (куда вставили токен)
            row.createCell(10).setCellValue(newRow.hardwareInfo)

            // Колонка 12: Дата изъятия (пусто при создании)
            row.createCell(11).setCellValue(newRow.removeDate)

            // Колонка 13: Ф.И.О. сотрудника, изъявшего СКЗИ
            row.createCell(12).setCellValue(newRow.removerFio)

            // Колонка 14: Номер акта уничтожения ключевых документов
            row.createCell(13).setCellValue(newRow.destructionDoc)

            // Колонка 15: Примечание
            row.createCell(14).setCellValue(newRow.comment)

            // =========================================================================

            // Перезаписываем файл
            FileOutputStream(file).use { fos ->
                workbook.write(fos)
            }
            workbook.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * Проставляет дату изъятия и ФИО изъявшего для КЭП по его порядковому номеру № п/п
     */
    fun revokeKeyRow(rowId: String, removeDate: String, removerFio: String): Boolean {
        val file = File(EXCEL_FILE_PATH)
        if (!file.exists()) return false

        try {
            val fis = FileInputStream(file)
            val workbook = XSSFWorkbook(fis)
            val sheet = workbook.getSheetAt(0)
            fis.close()

            var success = false
            // Ищем строку с нужным ID (начиная с 4-й строки данных)
            for (i in 2..sheet.lastRowNum) {
                val row = sheet.getRow(i) ?: continue
                val currentId = row.getCell(0)?.toString()?.substringBefore(".") ?: ""

                if (currentId == rowId) {
                    // Колонка 12 (Индекс 11) — Дата изъятия
                    val dateCell = row.getCell(11) ?: row.createCell(11)
                    dateCell.setCellValue(removeDate)

                    // Колонка 13 (Индекс 12) — Ф.И.О. изъявшего
                    val fioCell = row.getCell(12) ?: row.createCell(12)
                    fioCell.setCellValue(removerFio)

                    success = true
                    break
                }
            }

            if (success) {
                // Перезаписываем файл Excel с изменениями
                FileOutputStream(file).use { fos ->
                    workbook.write(fos)
                }
            }
            workbook.close()
            return success
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }
}

@Composable
fun Journal() {
    val scope = rememberCoroutineScope()

    // Подрежимы внутри вкладки Журнал: 0 - Просмотр Excel, 1 - Неучтенные КЭП из Базы
    var subTab by remember { mutableStateOf(0) }

    // Списки для хранения данных
    var excelRows by remember { mutableStateOf(listOf<JournalRow>()) }
    var unassignedCerts by remember { mutableStateOf(listOf<CertInfo>()) }
    var isLoading by remember { mutableStateOf(false) }

    // Поиск по ФИО
    var searchQuery by remember { mutableStateOf("") }

    // Функция для обновления данных из Excel и SQLite
    fun refreshData() {
        scope.launch {
            isLoading = true
            excelRows = withContext(Dispatchers.IO) { ExcelJournalManager.readJournal() }
            val dbCerts = withContext(Dispatchers.IO) { DatabaseManager.getAllRecords() }

            unassignedCerts = dbCerts.filter { cert ->
                val cleanDbId = cert.hardwareId.trim().substringBefore(".")
                // Приводим ФИО из базы к общему виду (нижний регистр, без лишних пробелов)
                val cleanDbFio = cert.subject.trim().lowercase()

                val alreadyInExcel = excelRows.any { row ->
                    val cleanExcelId = row.serialSKZI.trim().substringBefore(".")
                    val cleanExcelFio = row.userFio.trim().lowercase()

                    if (cleanDbId.isBlank() || cleanDbId == "ID не найден") return@any false

                    // Железобетонное условие: совпали И серийник токена, И ФИО сотрудника
                    val idMatches = cleanDbId.equals(cleanExcelId, ignoreCase = true)

                    // Используем contains, так как в Excel ФИО может быть записано чуть иначе (например, с инициалами)
                    val fioMatches = cleanExcelFio.contains(cleanDbFio) || cleanDbFio.contains(cleanExcelFio)

                    idMatches && fioMatches
                }

                // Оставляем в списке неучтенных, если такой связки "Человек + Токен" еще нет в Excel
                !alreadyInExcel
            }
            isLoading = false
        }
    }

    // Триггер загрузки при старте вкладки
    LaunchedEffect(Unit) {
        refreshData()
    }

    // На лету фильтруем строки, которые прочитали из Excel
    val filteredExcelRows = remember(searchQuery, excelRows) {
        if (searchQuery.isBlank()) {
            excelRows
        } else {
            // Фильтруем по колонке userFio (7-я колонка, куда пишется ФИО)
            excelRows.filter { it.userFio.contains(searchQuery, ignoreCase = true) }
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Шапка и переключатели подрежимов
        Row(
            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp).height(56.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.weight(0.9f)) {
                Button(
                    onClick = { subTab = 0 },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (subTab == 0) EndfieldColors.GoldDim else EndfieldColors.Bg0
                    ),
                    shape = CutCornerShape(0.dp),
                    modifier = Modifier.fillMaxHeight().border(1.dp, if (subTab == 0) EndfieldColors.Gold else EndfieldColors.GoldBorder)
                ) {
                    Text("ПРОСМОТР ЖУРНАЛА (EXCEL)", color = if (subTab == 0) EndfieldColors.Gold else EndfieldColors.GoldMuted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                }

                Button(
                    onClick = { subTab = 1 },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (subTab == 1) EndfieldColors.GoldDim else EndfieldColors.Bg0
                    ),
                    shape = CutCornerShape(0.dp),
                    modifier = Modifier.fillMaxHeight().border(1.dp, if (subTab == 1) EndfieldColors.Gold else EndfieldColors.GoldBorder)
                ) {
                    BadgedBox(badge = {
                        if (unassignedCerts.isNotEmpty()) {
                            Badge(containerColor = EndfieldColors.Gold) { Text(unassignedCerts.size.toString(), color = EndfieldColors.Bg0) }
                        }
                    }) {
                        Text("НЕУЧТЕННЫЕ КЭП В АРХИВЕ", color = if (subTab == 1) EndfieldColors.Gold else EndfieldColors.GoldMuted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    }
                }

                if (subTab == 0) {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        placeholder = { Text("Поиск по ФИО в журнале...", color = EndfieldColors.TxtMuted, fontSize = 11.sp) },
                        modifier = Modifier.fillMaxHeight().fillMaxWidth().padding(end = 12.dp),
                        singleLine = true,
                        textStyle = TextStyle(fontSize = 12.sp, fontFamily = FontFamily.Monospace),
                        colors = OutlinedTextFieldDefaults.colors(
                            // Цвет текста внутри поля
                            focusedTextColor = EndfieldColors.White,
                            unfocusedTextColor = EndfieldColors.White,

                            // Цвет рамки вокруг поля
                            focusedBorderColor = EndfieldColors.Gold,
                            unfocusedBorderColor = EndfieldColors.GoldBorder,

                            // Цвет плейсхолдера
                            focusedPlaceholderColor = EndfieldColors.TxtMuted,
                            unfocusedPlaceholderColor = EndfieldColors.TxtMuted
                        )
                    )
                }
            }

            // Кнопка Перечитать/Обновить файлы
            Button(
                onClick = { refreshData() },
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                modifier = Modifier.fillMaxHeight().weight(0.1f).border(1.dp, EndfieldColors.GoldBorder, CutCornerShape(4.dp))
            ) {
                Text("ОБНОВИТЬ", color = EndfieldColors.White, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
        }

        if (isLoading) {
            Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = EndfieldColors.Gold)
            }
        } else {
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                when (subTab) {
                    0 -> ExcelTableView(
                        rows = filteredExcelRows,
                        onDataChanged = {
                            refreshData()
                        }
                    )
                    1 -> UnassignedCertsView(unassignedCerts, onAdded = { refreshData() })
                }
            }
        }
    }
}

/**
 * Компонент 1. Сетка для отображения колонок журнала
 */
@Composable
fun ExcelTableView(rows: List<JournalRow>, onDataChanged: () -> Unit) {
    val horizontalScrollState = rememberScrollState()
    val verticalListState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    // Стейты для управления окном редактирования/изъятия
    var selectedRowForEdit by remember { mutableStateOf<JournalRow?>(null) }
    var removeDateInput by remember { mutableStateOf(todaysDate()) } // автоматом ставит сегодняшнее число
    var removerFioInput by remember { mutableStateOf(ExcelJournalManager.defaultInstaller) } // берет админа из настроек

    val columnWidths = listOf(50.dp, 150.dp, 130.dp, 120.dp, 120.dp, 150.dp, 180.dp, 120.dp, 180.dp, 120.dp, 140.dp, 100.dp, 160.dp, 130.dp, 150.dp)
    val headers = listOf("№ п/п", "Наименование СКЗИ", "Серийный номер СКЗИ", "№ экз. ключевых док.", "От кого получены", "Дата и № сопр. письма", "Ф.И.О. пользователя", "Дата и расписка", "Ф.И.О. установщика", "Дата установки", "№ аппаратных средств", "Дата изъятия", "Ф.И.О. изъявшего", "№ акта уничтож.", "Примечание")

    if (rows.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize().background(EndfieldColors.Bg0).border(1.dp, EndfieldColors.GoldBorder), contentAlignment = Alignment.Center) {
            Text("Журнал пуст или записей по запросу не найдено", color = EndfieldColors.TxtMuted, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }
        return
    }

    Box(modifier = Modifier.fillMaxSize().background(EndfieldColors.Bg0).border(1.dp, EndfieldColors.GoldBorder)) {
        Column(modifier = Modifier.fillMaxSize().horizontalScroll(horizontalScrollState)) {
            // Шапка таблицы
            Row(modifier = Modifier.background(EndfieldColors.GoldDim)) {
                headers.forEachIndexed { index, text ->
                    Box(modifier = Modifier.width(columnWidths[index]).height(50.dp).border(0.5.dp, EndfieldColors.GoldBorder).padding(4.dp), contentAlignment = Alignment.Center) {
                        Text(text, color = EndfieldColors.Gold, fontSize = 10.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center, fontFamily = FontFamily.Monospace)
                    }
                }
            }

            // Строки данных
            LazyColumn(state = verticalListState, modifier = Modifier.weight(1f)) {
                items(rows) { row ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(0.2.dp, EndfieldColors.GoldBorder.copy(alpha = 0.3f))
                            // 🔥 ДЕЛАЕМ СТРОКУ КЛИКАБЕЛЬНОЙ ДЛЯ РЕДАКТИРОВАНИЯ
                            .clickable { selectedRowForEdit = row }
                            .background(if (row.removeDate.isNotBlank()) Color.Red.copy(alpha = 0.1f) else Color.Transparent) // Подсветим уже изъятые КЭП
                    ) {
                        val cells = listOf(row.id, row.nameSKZI, row.serialSKZI, row.keyNumbers, row.receivedFrom, row.receivedDoc, row.userFio, row.receivedDate, row.installerFio, row.installDate, row.hardwareInfo, row.removeDate, row.removerFio, row.destructionDoc, row.comment)
                        cells.forEachIndexed { index, cellText ->
                            Box(modifier = Modifier.width(columnWidths[index]).height(42.dp).border(0.5.dp, EndfieldColors.GoldBorder.copy(alpha = 0.5f)).padding(6.dp), contentAlignment = Alignment.CenterStart) {
                                Text(cellText, color = if(row.removeDate.isNotBlank()) EndfieldColors.TxtMuted else EndfieldColors.White, fontSize = 11.sp, maxLines = 2, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }
        }

        // Полосы прокрутки
        VerticalScrollbar(adapter = rememberScrollbarAdapter(verticalListState), modifier = Modifier.align(Alignment.CenterEnd).fillMaxHeight())
        HorizontalScrollbar(adapter = rememberScrollbarAdapter(horizontalScrollState), modifier = Modifier.align(Alignment.BottomStart).fillMaxWidth())
    }

    // =========================================================================
    // ДИАЛОГОВОЕ ОКНО ИЗЪЯТИЯ / РЕДАКТИРОВАНИЯ СТРОКИ ЖУРНАЛА
    // =========================================================================
    selectedRowForEdit?.let { row ->
        AlertDialog(
            onDismissRequest = { selectedRowForEdit = null },
            title = { Text("ИЗЪЯТИЕ / ОТЗЫВ СКЗИ (Запись №${row.id})", color = EndfieldColors.Gold, fontSize = 14.sp, fontFamily = FontFamily.Monospace) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Пользователь: ${row.userFio}\nСерийный номер: ${row.serialSKZI}", color = EndfieldColors.White, fontSize = 12.sp)

                    OutlinedTextField(
                        value = removeDateInput,
                        onValueChange = { removeDateInput = it },
                        label = { Text("Дата изъятия СКЗИ", color = EndfieldColors.TxtMuted) },
                        colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = EndfieldColors.Gold, unfocusedBorderColor = EndfieldColors.GoldBorder, focusedTextColor = EndfieldColors.White, unfocusedTextColor = EndfieldColors.White),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = removerFioInput,
                        onValueChange = { removerFioInput = it },
                        label = { Text("Ф.И.О. изъявшего сотрудника", color = EndfieldColors.TxtMuted) },
                        colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = EndfieldColors.Gold, unfocusedBorderColor = EndfieldColors.GoldBorder, focusedTextColor = EndfieldColors.White, unfocusedTextColor = EndfieldColors.White),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch(Dispatchers.IO) {
                            val ok = ExcelJournalManager.revokeKeyRow(row.id, removeDateInput, removerFioInput)
                            if (ok) {
                                withContext(Dispatchers.Main) {
                                    selectedRowForEdit = null
                                    onDataChanged() // Перечитываем Excel, чтобы обновить таблицу на экране!
                                }
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.Gold)
                ) {
                    Text("ВНЕСТИ В ЖУРНАЛ", color = EndfieldColors.Bg0, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { selectedRowForEdit = null }) {
                    Text("ОТМЕНА", color = EndfieldColors.TxtMuted)
                }
            },
            containerColor = EndfieldColors.Bg1,
            modifier = Modifier.border(1.dp, EndfieldColors.GoldBorder, CutCornerShape(0.dp))
        )
    }
}

/**
 * Компонент 2. Список КЭП, которых еще нет в Excel-журнале
 */
@Composable
fun UnassignedCertsView(certs: List<CertInfo>, onAdded: () -> Unit) {
    val scope = rememberCoroutineScope()

    if (certs.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize().background(EndfieldColors.Bg0).border(1.dp, EndfieldColors.GoldBorder), contentAlignment = Alignment.Center) {
            Text("Все КЭП из локального архива SQLite уже внесены в Excel журнал.", color = EndfieldColors.Teal, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }
        return
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(certs) { cert ->
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).border(1.dp, EndfieldColors.GoldBorder, CutCornerShape(0.dp)),
                shape = CutCornerShape(0.dp),
                colors = CardDefaults.cardColors(containerColor = EndfieldColors.Bg0)
            ) {
                Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("${cert.subject}", color = EndfieldColors.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        Text("Серийник СКЗИ: ${cert.hardwareId}", color = EndfieldColors.Gold, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                        Text("Контейнер: ${cert.containerPath.substringAfterLast("\\")}", color = EndfieldColors.TxtMuted, fontSize = 11.sp)
                    }

                    Button(
                        onClick = {
                            scope.launch {
                                withContext(Dispatchers.IO) {
                                    // Формируем новую гостовскую строку
                                    val newRow = JournalRow(
                                        id = "", // Вычислится автоматически менеджером
                                        nameSKZI = "",
                                        serialSKZI = cert.hardwareId,
                                        // keyNumbers = "Контейнер ${cert.containerPath.substringAfterLast("\\")}",
                                        keyNumbers = "",
                                        receivedFrom = "",
                                        receivedDoc = "",
                                        userFio = cert.subject,
                                        receivedDate = todaysDate(),
                                        installerFio = "", // Можно будет брать из настроек
                                        installDate = todaysDate(),
                                        hardwareInfo = "",
                                        removeDate = "", removerFio = "", destructionDoc = "", comment = ""
                                    )
                                    ExcelJournalManager.appendRow(newRow)
                                }
                                onAdded() // Обновляем списки на UI
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.Gold),
                        shape = CutCornerShape(0.dp)
                    ) {
                        Text("ВНЕСТИ В EXCEL", color = EndfieldColors.Bg0, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    }
                }
            }
        }
    }
}