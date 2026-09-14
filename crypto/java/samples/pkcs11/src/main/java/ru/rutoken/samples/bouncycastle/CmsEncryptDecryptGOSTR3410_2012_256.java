/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle;

import com.sun.jna.NativeLong;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.CreateKeyPairAndCertificateGOSTR3410_2012_256;
import ru.rutoken.samples.bouncycastle.cmsoperations.CmsOperations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.bouncycastle.cms.CMSAlgorithm.GOST28147_GCFB;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_CATEGORY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKC_X_509;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_CERTIFICATE_CATEGORY_TOKEN_USER;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_INVALID_HANDLE;
import static ru.rutoken.samples.utils.CommonUtil.printHex;
import static ru.rutoken.samples.utils.CommonUtil.printString;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;
import static ru.rutoken.samples.utils.Util.certificateToPem;
import static ru.rutoken.samples.utils.Util.cmsToPem;
import static ru.rutoken.samples.utils.Util.getX509Certificate;

/**
 * Sample of CMS encrypting and decrypting with GOST 28147-89 using Bouncy Castle.
 * Expects GOST R 3410.2012-256 certificate and GOST R 3410.2012-256 key pair on the token, you should run
 * {@link CreateKeyPairAndCertificateGOSTR3410_2012_256} sample to create them.
 */
public class CmsEncryptDecryptGOSTR3410_2012_256 {
    /**
     * Template for finding certificate
     */
    private static final CK_ATTRIBUTE[] certificateTemplate;
    private static final byte[] DATA_TO_ENCRYPT = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
        certificateTemplate[2].setAttr(CKA_ID,
                CreateKeyPairAndCertificateGOSTR3410_2012_256.KEY_PAIR_ID); // Certificate ID
        certificateTemplate[3].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
    }

    public static void main(String[] args) {
        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        try {
            CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);
            println("Printing info about all certificates:");
            Pkcs11Operations.printAllCertificatesInfo(pkcs11, session);

            // Side A encrypts data using Side B's certificate
            // You can get certificate from some database, we'll get it from the token for simplicity
            println("Finding certificate for encrypting");
            byte[] certificateValue = Pkcs11Operations.getFirstCertificateValue(pkcs11, session, certificateTemplate);
            printString("Certificate value in PEM:", certificateToPem(certificateValue));

            println("Encrypting data to CMS using Bouncy Castle");
            printHex("Data to encrypt:", DATA_TO_ENCRYPT);
            byte[] encryptedCms = cmsEncrypt(DATA_TO_ENCRYPT, certificateValue, GOST28147_GCFB);
            printString("Encrypted CMS in PEM:", cmsToPem(encryptedCms));

            // Side B has corresponding key pair on Rutoken device and uses it to decrypt data from CMS
            println("Decrypting data from CMS using Bouncy Castle");
            byte[] decryptedData = cmsDecrypt(pkcs11, session, certificateValue, encryptedCms);
            if (!Arrays.equals(DATA_TO_ENCRYPT, decryptedData))
                throw new RuntimeException("Decrypted data does not match original");
            printHex("Decrypted data:", decryptedData);
            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            if (e instanceof CMSException && e.getCause() instanceof InvalidKeyException) {
                printlnError("You are probably using jre 8 version older than 161 which by default forbids \n" +
                        "usage of keys longer than 128 bits (you can search \n" +
                        "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files); \n" +
                        "consider migrating to jre 8 161 or newer, or manually replace file \n" +
                        "<path_to_jre>/lib/security/local_policy.jar by newer file local_policy.jar \n" +
                        "that you can download from oracle.com \n" +
                        "(https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)");
            }
            e.printStackTrace();
        } finally {
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }

    /**
     * Create CMS with "Enveloped-data Content Type"
     */
    public static byte[] cmsEncrypt(byte[] data, byte[] certificateValue,
                                    ASN1ObjectIdentifier contentEncryptionAlgorithm)
            throws CertificateException, CMSException, IOException {
        byte[] encryptedCms =
                CmsOperations.encryptByKeyTransportProtocol(data, certificateValue, contentEncryptionAlgorithm);
        println("Data has been encrypted successfully");
        return encryptedCms;
    }

    /**
     * Decrypt data from CMS with "Enveloped-data Content Type"
     */
    public static byte[] cmsDecrypt(Pkcs11 pkcs11, NativeLong session, byte[] certificateValue, byte[] encryptedCms)
            throws CMSException, CertificateException, Pkcs11Exception, IOException {
        NativeLong privateKey = Pkcs11Operations.findPrivateKeyByCertificateValue(pkcs11, session, certificateValue);
        X509Certificate recipientCertificate = getX509Certificate(new X509CertificateHolder(certificateValue));
        // Decrypting user may own multiple certificates and doesn't have to know with which certificate exactly
        // to decrypt the message, so you should pass all certificates owned by user to decryptor.
        // For simplicity, we pass only one certificate.
        List<X509Certificate> possibleRecipientsCertificates = Collections.singletonList(recipientCertificate);
        byte[] decryptedData = CmsOperations.decrypt(encryptedCms, session.longValue(), privateKey.longValue(),
                possibleRecipientsCertificates);
        println("Data has been decrypted successfully");
        return decryptedData;
    }
}
