package org.alex.project

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock

fun todaysDate(): String {
    fun LocalDateTime.format() = toString().substringBefore('T')
    val now = Clock.System.now()
    val zone = TimeZone.currentSystemDefault()
    return now.toLocalDateTime(zone).format()
}

@Composable
@Preview
fun App() {
    // Работа с табами
    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Сканер", "Архив", "Журнал", "Настройки")


    MaterialTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = EndfieldColors.Bg1
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                // Навигация
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, EndfieldColors.GoldBorder)
                        .padding(horizontal = 24.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.wrapContentWidth()
                    ) {
                        tabs.forEachIndexed { i, item ->
                            HorizontalNavigationItem(
                                title = item,
                                isSelected = selectedTab == i,
                                onSelect = {selectedTab = i}
                                )
                        }

                        Spacer(modifier = Modifier.weight(1f))

                        Text(
                            text = todaysDate(),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            color = EndfieldColors.TxtMuted
                        )
                    }
                }

                // Контент
                Column(
                    modifier = Modifier
                        .weight(0.7f)
                        .fillMaxWidth()
                        .padding(24.dp),
                    verticalArrangement = Arrangement.Top,
                    horizontalAlignment = Alignment.Start
                ) {
                    when (selectedTab) {
                        0 -> SkanToken() // Сканирование токенов
                        1 -> Arhive() // Архив
                        2 -> Journal() // Журнал
                        3 -> Settings() // Настрйоки
                    }
                }
            }
        }
    }
}

@Composable
fun HorizontalNavigationItem(title: String, isSelected: Boolean, onSelect: () -> Unit) {
    Box(
        modifier = Modifier
            // wrapContentWidth заставляет вкладку растягиваться ровно под длину текста
            .wrapContentWidth()
            .height(38.dp) // Чуть уменьшили высоту для горизонтального меню
            .background(
                color = if (isSelected) EndfieldColors.GoldDim else Color.Transparent,
                shape = CutCornerShape(topStart = 0.dp, bottomEnd = 6.dp)
            )
            .border(
                width = 1.dp,
                color = if (isSelected) EndfieldColors.Gold else EndfieldColors.GoldBorder,
                shape = CutCornerShape(topStart = 0.dp, bottomEnd = 6.dp)
            )
            .clickable(onClick = onSelect)
            // Паддинги внутри вкладки, чтобы текст не лип к её рамкам
            .padding(horizontal = 16.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = title,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                fontSize = 12.sp,
                fontWeight = if (isSelected) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.Normal,
                color = if (isSelected) EndfieldColors.Gold else EndfieldColors.GoldMuted
            )

            if (isSelected) {
                // Вместо левого маркера сделали аккуратную золотую полоску СНИЗУ под текстом
                Spacer(modifier = Modifier.height(2.dp))
                Box(
                    modifier = Modifier
                        .width(16.dp)
                        .height(2.dp)
                        .background(EndfieldColors.Gold)
                )
            }
        }
    }
}