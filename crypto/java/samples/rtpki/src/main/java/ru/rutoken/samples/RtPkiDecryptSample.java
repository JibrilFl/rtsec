/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.ptr.PointerByReference;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.rtpki.RtPki;
import ru.rutoken.rtpki.RtPkiData;
import ru.rutoken.rtpki.RtPkiDecryptParams;
import ru.rutoken.rtpki.RtPkiEncryptParams;
import ru.rutoken.rtpki.RtPkiResult;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11TokenUtils;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.rtpkiutils.RtPkiException;
import ru.rutoken.samples.rtpkiutils.RtPkiLibrary;

import java.nio.charset.StandardCharsets;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_CATEGORY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKC_X_509;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PRIVATE_KEY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PUBLIC_KEY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_INVALID_HANDLE;
import static ru.rutoken.pkcs11jna.Pkcs11Tc26Constants.CKM_GOST_KEG;
import static ru.rutoken.rtpki.RtPkiCmsCipherAlgorithm.RT_PKI_CMS_CIPHER_MAGMA_CTR_ACPKM;
import static ru.rutoken.rtpki.RtPkiDataFormat.RT_PKI_DER;
import static ru.rutoken.rtpki.RtPkiDataFormat.RT_PKI_PEM;
import static ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken;
import static ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations.logoutAndFinalizePkcs11Library;
import static ru.rutoken.samples.utils.CommonUtil.printHex;
import static ru.rutoken.samples.utils.CommonUtil.printString;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;
import static ru.rutoken.samples.utils.Constants.DATA;
import static ru.rutoken.samples.utils.Constants.RECIPIENT_CERTIFICATE_PEM;

/**
 * Sample of CMS encrypting and decrypting with GOST R 34.12 2018 using rtpki. Expects GOST R 3410.2012-256 certificate
 * and key pair on the token, you should run {@code CreateKeyPairAndCertificateGOSTR3410_2012_256} sample in the :pkcs11
 * module to create it.
 */
public class RtPkiDecryptSample {
    /**
     * Template for finding GOST R 3410.2012-256 certificate
     */
    private final static CK_ATTRIBUTE[] certificateTemplate;

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(3);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[2].setAttr(CKA_CERTIFICATE_CATEGORY, 1);
    }

    public static void main(String[] args) {
        println("-----------------------------------------------------------");
        println("CMS Decrypt Sample");
        println("-----------------------------------------------------------");

        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        RtPki rtPki = RtPkiLibrary.getRtPkiInterface();

        int rtPkiRv;
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        PointerByReference rtPkiSessionPtr = new PointerByReference();
        try {
            PointerByReference functionListPtr = new PointerByReference();
            NativeLong rtPkcs11Rv = pkcs11.C_GetFunctionList(functionListPtr);
            Pkcs11Exception.throwIfNotOk("C_GetFunctionList failed", rtPkcs11Rv);

            NativeLong token = initializePkcs11AndLoginToFirstToken(pkcs11, session);

            if (!CommonPkcs11TokenUtils.isMechanismSupported(pkcs11, token, CKM_GOST_KEG))
                throw new UnsupportedOperationException("Token doesn't support the GOST 34.12-2018 KEG mechanism.");

            println("Finding certificate...");
            NativeLong certificateHandle = CommonPkcs11Operations.findFirstObject(pkcs11, session, certificateTemplate);
            byte[] certificateValueBytes =
                    CommonPkcs11Operations.getCertificateValue(pkcs11, session, certificateHandle);
            printHex("Certificate value:", certificateValueBytes);

            byte[] certificateIdBytes = Pkcs11Operations.getCertificateId(pkcs11, session, certificateHandle);
            printHex("Certificate id:", certificateIdBytes);

            println("Creating CMS with enveloped data");
            rtPkiRv = rtPki.rt_pki_initialize();
            RtPkiException.throwIfNotOk("rt_pki_initialize", rtPkiRv);

            RtPkiData.ByReference[] recipients = (RtPkiData.ByReference[]) (new RtPkiData.ByReference()).toArray(2);
            recipients[0].setData(RT_PKI_PEM, RECIPIENT_CERTIFICATE_PEM);
            recipients[1].setData(RT_PKI_DER, certificateValueBytes);

            RtPkiEncryptParams encryptParams = new RtPkiEncryptParams(RT_PKI_CMS_CIPHER_MAGMA_CTR_ACPKM, recipients);
            RtPkiData envelopedData = new RtPkiData();
            rtPkiRv = rtPki.rt_pki_cms_encrypt(encryptParams, DATA, new NativeLong(DATA.length), envelopedData);
            RtPkiException.throwIfNotOk("rt_pki_cms_encrypt", rtPkiRv);

            envelopedData.value = new Memory(envelopedData.valueSize.longValue());
            rtPkiRv = rtPki.rt_pki_cms_encrypt(encryptParams, DATA, new NativeLong(DATA.length), envelopedData);
            RtPkiException.throwIfNotOk("rt_pki_cms_encrypt", rtPkiRv);

            byte[] envelopedDataBytes = envelopedData.value.getByteArray(0, envelopedData.valueSize.intValue());
            printString("Enveloped data:", new String(envelopedDataBytes, StandardCharsets.UTF_8));

            println("Decrypting enveloped data");
            rtPkiRv = rtPki.rt_pki_create_p11_session(rtPkiSessionPtr, functionListPtr.getValue(), session);
            RtPkiException.throwIfNotOk("rt_pki_create_p11_session", rtPkiRv);

            CK_ATTRIBUTE[] publicKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);
            publicKeyTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
            publicKeyTemplate[1].setAttr(CKA_ID, certificateIdBytes);
            NativeLong publicKeyHandle = CommonPkcs11Operations.findFirstObject(pkcs11, session, publicKeyTemplate);

            CK_ATTRIBUTE[] privateKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);
            privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
            privateKeyTemplate[1].setAttr(CKA_ID, certificateIdBytes);
            NativeLong privateKeyHandle = CommonPkcs11Operations.findFirstObject(pkcs11, session, privateKeyTemplate);

            RtPkiDecryptParams decryptParams =
                    new RtPkiDecryptParams(rtPkiSessionPtr.getValue(), publicKeyHandle, privateKeyHandle);
            NativeLongByReference decryptedDataSize = new NativeLongByReference();
            rtPkiRv = rtPki.rt_pki_cms_decrypt(decryptParams, envelopedData, null, decryptedDataSize);
            RtPkiException.throwIfNotOk("rt_pki_cms_decrypt", rtPkiRv);

            byte[] decryptedData = new byte[decryptedDataSize.getValue().intValue()];
            rtPkiRv = rtPki.rt_pki_cms_decrypt(decryptParams, envelopedData, decryptedData, decryptedDataSize);
            RtPkiException.throwIfNotOk("rt_pki_cms_decrypt", rtPkiRv);

            printHex("Decrypted data:", decryptedData);
            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            rtPkiRv = rtPki.rt_pki_destroy_p11_session(rtPkiSessionPtr.getValue());
            if (rtPkiRv != RtPkiResult.RT_PKI_OK) {
                printlnError("rt_pki_destroy_p11_session failed, error code: 0x" + Integer.toHexString(rtPkiRv));
            }

            rtPkiRv = rtPki.rt_pki_finalize();
            if (rtPkiRv != RtPkiResult.RT_PKI_OK) {
                printlnError("rt_pki_finalize failed, error code: 0x" + Integer.toHexString(rtPkiRv));
            }

            logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }
}
