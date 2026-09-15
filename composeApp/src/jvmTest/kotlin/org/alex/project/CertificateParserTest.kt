package org.alex.project

import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals

class CertificateParserTest {
    @Test
    fun `reads standard and russian subject attributes`() {
        // ИНН и СНИЛС записаны как DER PrintableString с нестандартными OID.
        val principal = X500Principal(
            "CN=Иванов Иван Иванович, T=Врач, " +
                    "1.2.840.113549.1.9.1=#160E6976616E6F7640746573742E7275, " +
                    "1.2.643.3.131.1.1=#130C313233343536373839303132, " +
                    "1.2.643.100.3=#130B3132333435363738393031"
        )

        val attributes = CertificateParser.subjectAttributes(principal)

        assertEquals("Иванов Иван Иванович", attributes["2.5.4.3"])
        assertEquals("Врач", attributes["2.5.4.12"])
        assertEquals("ivanov@test.ru", attributes["1.2.840.113549.1.9.1"])
        assertEquals("123456789012", attributes["1.2.643.3.131.1.1"])
        assertEquals("12345678901", attributes["1.2.643.100.3"])
    }
}
