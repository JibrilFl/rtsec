/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle;

import com.sun.jna.NativeLong;

import org.bouncycastle.cms.CMSException;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.CreateKeyPairAndCertificateGOSTR3410_2001;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import java.security.InvalidKeyException;
import java.util.Arrays;

import static org.bouncycastle.cms.CMSAlgorithm.GOST28147_GCFB;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.bouncycastle.CmsEncryptDecryptGOSTR3410_2012_256.cmsDecrypt;
import static ru.rutoken.samples.bouncycastle.CmsEncryptDecryptGOSTR3410_2012_256.cmsEncrypt;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of CMS encrypting and decrypting with GOST 28147-89 using Bouncy Castle.
 * Expects GOST R 3410.2001 certificate and GOST R 3410.2001 key pair on the token, you should run
 * {@link CreateKeyPairAndCertificateGOSTR3410_2001} sample to create them.
 */
public class CmsEncryptDecryptGOSTR3410_2001 {
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
                CreateKeyPairAndCertificateGOSTR3410_2001.KEY_PAIR_ID); // Certificate ID
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
}
