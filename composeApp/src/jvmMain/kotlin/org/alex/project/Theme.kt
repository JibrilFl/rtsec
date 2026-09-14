package org.alex.project

import androidx.compose.ui.graphics.Color

object EndfieldColors {

    val Bg1 = Color(0xFF1E1E24) // Был 0xFF0B0A10 (сделали графитовым)
    val Bg0 = Color(0xFF141419) // Был 0xFF07060A (боковая панель чуть темнее)
    val Bg2 = Color(0xFF2A2A32) // Фон карточек

    // Чистый, благородный золотой (основной акцент, активный таб, рамки)
    val Gold = Color(0xFFE8B825)

    // Мягкий приглушенный золотой (для текста неактивных табов и второстепенных меток)
    val GoldMuted = Color(0xFF8A7E5A)

    // Полупрозрачный янтарный (фон активного таба / подложка)
    // Альфа-канал 0x18 (около 10% непрозрачности) — создает аккуратное футуристичное свечение
    val GoldDim = Color(0x18E8B825)

    // Контрастный темный золотой для тонких технологичных рамок
    val GoldBorder = Color(0x3FE8B825)

    val Red = Color(0xFFE84040)
    val RedDim = Color(0x18E84040)
    val Teal = Color(0xFF2AE8C8)

    val Txt = Color(0xFFD4C89A)
    val TxtMuted = Color(0xFF8A7E5A)
    val White = Color(0xFFF0E8CC)

    val Steel = Color(0xFF1C1A28)
}