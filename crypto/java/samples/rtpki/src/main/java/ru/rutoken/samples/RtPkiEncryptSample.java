/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;

import ru.rutoken.rtpki.RtPki;
import ru.rutoken.rtpki.RtPkiData;
import ru.rutoken.rtpki.RtPkiEncryptParams;
import ru.rutoken.rtpki.RtPkiResult;
import ru.rutoken.samples.rtpkiutils.RtPkiException;
import ru.rutoken.samples.rtpkiutils.RtPkiLibrary;

import java.nio.charset.StandardCharsets;

import static ru.rutoken.rtpki.RtPkiCmsCipherAlgorithm.RT_PKI_CMS_CIPHER_KUZNECHIK_CTR_ACPKM;
import static ru.rutoken.rtpki.RtPkiDataFormat.RT_PKI_PEM;
import static ru.rutoken.samples.utils.CommonUtil.printString;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;
import static ru.rutoken.samples.utils.Constants.DATA;
import static ru.rutoken.samples.utils.Constants.RECIPIENT_CERTIFICATE_PEM;

/**
 * Sample of CMS encrypting with GOST R 34.12 2018 using rtpki.
 */
public class RtPkiEncryptSample {
    public static void main(String[] args) {
        println("-----------------------------------------------------------");
        println("CMS Encrypt Sample");
        println("-----------------------------------------------------------");

        RtPki rtPki = RtPkiLibrary.getRtPkiInterface();
        int rv;
        try {
            rv = rtPki.rt_pki_initialize();
            RtPkiException.throwIfNotOk("rt_pki_initialize", rv);

            RtPkiData.ByReference[] recipients = (RtPkiData.ByReference[]) (new RtPkiData.ByReference()).toArray(1);
            recipients[0].setData(RT_PKI_PEM, RECIPIENT_CERTIFICATE_PEM);

            RtPkiEncryptParams encryptParams =
                    new RtPkiEncryptParams(RT_PKI_CMS_CIPHER_KUZNECHIK_CTR_ACPKM, recipients);
            RtPkiData result = new RtPkiData();
            rv = rtPki.rt_pki_cms_encrypt(encryptParams, DATA, new NativeLong(DATA.length), result);
            RtPkiException.throwIfNotOk("rt_pki_cms_encrypt", rv);

            result.value = new Memory(result.valueSize.longValue());
            rv = rtPki.rt_pki_cms_encrypt(encryptParams, DATA, new NativeLong(DATA.length), result);
            RtPkiException.throwIfNotOk("rt_pki_cms_encrypt", rv);

            byte[] envelopedDataBytes = result.value.getByteArray(0, result.valueSize.intValue());
            printString("Enveloped data:", new String(envelopedDataBytes, StandardCharsets.UTF_8));

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            rv = rtPki.rt_pki_finalize();
            if (rv != RtPkiResult.RT_PKI_OK) {
                printlnError("rt_pki_finalize failed, error code: 0x" + Integer.toHexString(rv));
            }
        }
    }
}
