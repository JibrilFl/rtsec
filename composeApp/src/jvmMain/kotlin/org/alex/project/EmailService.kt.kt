package org.alex.project

import jakarta.mail.*
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import java.util.Properties

object EmailService {
    // Настройки твоего почтового ящика, С КОТОРОГО уходят письма
    private const val SMTP_HOST = "" // или smtp.mail.ru
    private const val SMTP_PORT = ""
    private const val SENDER_EMAIL = ""
    private const val SENDER_PASSWORD = "" // Пароль приложения!

    fun sendNotification(toEmail: String, subjectName: String, validTo: String) {
        val props = Properties().apply {
            put("mail.smtp.host", SMTP_HOST)
            put("mail.smtp.port", SMTP_PORT)
            put("mail.smtp.auth", "true")
            put("mail.smtp.ssl.enable", "true") // Явно включаем SSL защиту
            put("mail.smtp.socketFactory.port", SMTP_PORT)
            put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory")
        }

        val session = Session.getInstance(props, object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication(SENDER_EMAIL, SENDER_PASSWORD)
            }
        })

        try {
            val message = MimeMessage(session).apply {
                setFrom(InternetAddress(SENDER_EMAIL))
                setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail))
                subject = "Внимание: Истекает срок действия сертификата КЭП!"

                // Текст письма (можно использовать HTML-разметку)
                setContent("""
                    <h3>Уважаемый(а) $subjectName!</h3>
                    <p>Уведомляем вас, что срок действия вашего сертификата электронной подписи подходит к концу.</p>
                    <p><b>Дата окончания:</b> <span style="color: red;">$validTo</span></p>
                    <p>Пожалуйста, своевременно обратитесь в отдел ИТ для планового перевыпуска КЭП.</p>
                    <br>
                    <i>С уважением, автоматическая система уведомлений.</i>
                """.trimIndent(), "text/html; charset=utf-8")
            }

            Transport.send(message)
            println("Письмо успешно отправлено на адрес: $toEmail")
        } catch (e: Exception) {
            println("Ошибка при отправке письма на $toEmail:")
            e.printStackTrace()
        }
    }
}