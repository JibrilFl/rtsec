package org.alex.project

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Settings() {
    val scrollState = rememberScrollState()

    // Локальные стейты для текстовых полей, привязанные к синглтону
    var skziName by remember { mutableStateOf(ExcelJournalManager.defaultSkziName) }
    var defaultInstaller by remember { mutableStateOf(ExcelJournalManager.defaultInstaller) }
    var excelPath by remember { mutableStateOf(ExcelJournalManager.EXCEL_FILE_PATH) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "НАСТРОЙКИ АВТОЗАПОЛНЕНИЯ ЖУРНАЛА СКЗИ",
            color = EndfieldColors.Gold,
            fontSize = 14.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold
        )

        // 1. Поле "От кого получено"
        CustomSettingsField(
            value = defaultInstaller,
            onValueChange = {
                defaultInstaller = it
                ExcelJournalManager.defaultInstaller = it // Сразу влияет на логику записи!
            },
            label = "Администратор",
            placeholder = "ФИО"
        )

        // 2. Поле "Наименование СКЗИ"
        CustomSettingsField(
            value = skziName,
            onValueChange = {
                skziName = it
                ExcelJournalManager.defaultSkziName = it
            },
            label = "Наименование СКЗИ (вид токена)",
            placeholder = "РУТОКЕН"
        )

        // 3. Поле "Кто установил"
//        CustomSettingsField(
//            value = defaultInstaller,
//            onValueChange = {
//                defaultInstaller = it
//                ExcelJournalManager.defaultInstaller = it
//            },
//            label = "Ф.И.О. сотрудника, производившего установку (Колонка 9)",
//            placeholder = "Например: Иванов И.И. (Администратор ИБ)"
//        )

        // 4. Поле "Куда установлено"
//        CustomSettingsField(
//            value = hardwareInfo,
//            onValueChange = {
//                hardwareInfo = it
//                ExcelJournalManager.defaultHardware = it
//            },
//            label = "Номера аппаратных средств / ЭВМ (Колонка 11)",
//            placeholder = "Например: АРМ врача, инв. № или ПК КДЛ"
//        )

        Divider(color = EndfieldColors.GoldBorder, thickness = 1.dp, modifier = Modifier.padding(vertical = 8.dp))

        Text(
            text = "СИСТЕМНЫЕ НАСТРОЙКИ",
            color = EndfieldColors.Gold,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace
        )

        // 5. Путь к файлу Excel
        CustomSettingsField(
            value = excelPath,
            onValueChange = {
                excelPath = it
                ExcelJournalManager.EXCEL_FILE_PATH = it
            },
            label = "Путь к файлу журнала Excel (.xlsx)",
            placeholder = "C:/Users/.../skzi.xlsx"
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Кнопка сохранения конфигурации
        Button(
            onClick = {
                // Синхронизируем стейты UI с синглтоном менеджера
                ExcelJournalManager.defaultSkziName = skziName
                ExcelJournalManager.defaultInstaller = defaultInstaller
                ExcelJournalManager.EXCEL_FILE_PATH = excelPath

                // Физически пишем в файл на диске
                ExcelJournalManager.saveSettings()
            },
            colors = ButtonDefaults.buttonColors(containerColor = EndfieldColors.GoldDim),
            shape = androidx.compose.foundation.shape.CutCornerShape(0.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(45.dp)
                .border(1.dp, EndfieldColors.Gold)
        ) {
            Text(
                text = "СОХРАНИТЬ ИЗМЕНЕНИЯ",
                color = EndfieldColors.Gold,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomSettingsField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    placeholder: String
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(text = label, color = EndfieldColors.GoldMuted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            placeholder = { Text(text = placeholder, color = EndfieldColors.TxtMuted, fontSize = 12.sp) },
            modifier = Modifier.fillMaxWidth().height(48.dp), // Фиксированная компактная высота
            singleLine = true,
            textStyle = TextStyle(color = EndfieldColors.White, fontSize = 13.sp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = EndfieldColors.Gold,
                unfocusedBorderColor = EndfieldColors.GoldBorder,
                focusedContainerColor = EndfieldColors.Bg0,
                unfocusedContainerColor = EndfieldColors.Bg0
            )
        )
    }
}