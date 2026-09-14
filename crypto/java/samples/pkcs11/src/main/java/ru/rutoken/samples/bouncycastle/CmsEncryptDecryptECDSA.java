/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle;

import com.sun.jna.NativeLong;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSException;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.CreateKeyPairAndCertificateECDSA_SECP256K1;
import ru.rutoken.samples.CreateKeyPairAndCertificateECDSA_SECP256R1;
import ru.rutoken.samples.bouncycastle.cmsoperations.CmsOperations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11TokenUtils;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.bouncycastle.cms.CMSAlgorithm.AES128_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.AES128_WRAP;
import static org.bouncycastle.cms.CMSAlgorithm.ECDH_SHA256KDF;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_CATEGORY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_TOKEN;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKC_X_509;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_ECDH1_DERIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_CERTIFICATE_CATEGORY_TOKEN_USER;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_INVALID_HANDLE;
import static ru.rutoken.samples.bouncycastle.CmsEncryptDecryptGOSTR3410_2012_256.cmsDecrypt;
import static ru.rutoken.samples.utils.CommonUtil.printHex;
import static ru.rutoken.samples.utils.CommonUtil.printString;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;
import static ru.rutoken.samples.utils.Util.certificateToPem;
import static ru.rutoken.samples.utils.Util.cmsToPem;

/**
 * Sample of CMS encrypting and decrypting with ECDSA using Bouncy Castle. Expects ECDSA key pair with secp256k1 curve
 * and certificate on token by default, you should run {@link CreateKeyPairAndCertificateECDSA_SECP256K1} sample to
 * create them.
 */
public class CmsEncryptDecryptECDSA {
    /**
     * Template for finding certificate
     */
    private static final CK_ATTRIBUTE[] certificateTemplate;
    /**
     * Specifies the identifier of the key pair used in this sample. ECDSA key pair with secp256k1 curve is used by
     * default, but it can be replaced with ECDSA key pair with secp256r1 curve. CMS encryption/decryption using a ECDSA
     * key pairs with secp384r1 and secp521r1 curves is currently not working correctly.
     *
     * @see CreateKeyPairAndCertificateECDSA_SECP256K1#KEY_PAIR_ID
     * @see CreateKeyPairAndCertificateECDSA_SECP256R1#KEY_PAIR_ID
     */
    private static final byte[] ECDSA_KEY_PAIR_ID = CreateKeyPairAndCertificateECDSA_SECP256K1.KEY_PAIR_ID;

    private static final byte[] DATA_TO_ENCRYPT = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(5);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_TOKEN, true); // Certificate is stored on a token
        certificateTemplate[2].setAttr(CKA_ID, ECDSA_KEY_PAIR_ID); // Certificate ID
        certificateTemplate[3].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[4].setAttr(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
    }

    public static void main(String[] args) {
        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        try {
            NativeLong token = CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);

            if (!CommonPkcs11TokenUtils.isMechanismSupported(pkcs11, token, CKM_ECDH1_DERIVE))
                throw new UnsupportedOperationException("Token doesn't support the ECDH derive mechanism.");

            println("Printing info about all certificates:");
            Pkcs11Operations.printAllCertificatesInfo(pkcs11, session);

            // Side A encrypts data using Side B's certificate
            // You can get certificate from some database, we'll get it from the token for simplicity
            println("Finding certificate for encrypting");
            byte[] certificateValue = Pkcs11Operations.getFirstCertificateValue(pkcs11, session, certificateTemplate);
            printString("Certificate value in PEM:", certificateToPem(certificateValue));

            println("Encrypting data to CMS using Bouncy Castle");
            printHex("Data to encrypt:", DATA_TO_ENCRYPT);
            // You can specify key agreement and content encryption algorithms here
            byte[] encryptedCms =
                    cmsEncrypt(DATA_TO_ENCRYPT, certificateValue, ECDH_SHA256KDF, AES128_WRAP, AES128_CBC);
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
                                    ASN1ObjectIdentifier keyAgreementAlgorithmOID,
                                    ASN1ObjectIdentifier keyWrapAlgorithmOID,
                                    ASN1ObjectIdentifier contentEncryptionAlgorithmOID)
            throws CMSException, CertificateException, IOException {
        byte[] encryptedCms = CmsOperations.encryptByKeyAgreeProtocol(data, certificateValue, keyAgreementAlgorithmOID,
                keyWrapAlgorithmOID, contentEncryptionAlgorithmOID);
        println("Data has been encrypted successfully");

        return encryptedCms;
    }
}
