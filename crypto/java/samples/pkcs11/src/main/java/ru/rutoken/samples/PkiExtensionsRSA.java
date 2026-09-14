/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.ptr.PointerByReference;

import org.bouncycastle.asn1.x509.DigestInfo;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.pkcs11utils.*;

import java.io.IOException;
import java.util.Arrays;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of rtpkcs11ecp PKI extensions usage via JNA with RSA key pair.
 * Expects key pair and certificate on token, you should run
 * {@link CreateKeyPairAndCertificateRSA} sample to create them.
 */
public class PkiExtensionsRSA {
    /**
     * Template for finding certificate
     */
    private static final CK_ATTRIBUTE[] certificateTemplate;
    private final static byte[] DATA_TO_ENCRYPT = {'1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd'};
    private final static byte[] DATA_TO_SIGN = {'1', '2', '3', '3', '2', '1'};

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(5);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[2].setAttr(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
        certificateTemplate[3].setAttr(CKA_ID, CreateKeyPairAndCertificateRSA.KEY_PAIR_ID); // Certificate ID
        certificateTemplate[4].setAttr(CKA_PRIVATE, false); // Accessible without authentication
    }

    public static void main(String[] args) {
        RtPkcs11 pkcs11 = RtPkcs11Library.getPkcs11ExtendedInterface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);

        PointerByReference certificateInfo = new PointerByReference();
        try {
            CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);

            println("Finding certificate");
            NativeLong certificate = CommonPkcs11Operations.findFirstObject(pkcs11, session, certificateTemplate);

            byte[] certificateValue = CommonPkcs11Operations.getCertificateValue(pkcs11, session, certificate);
            printString("Certificate value in PEM:", certificateToPem(certificateValue));

            println("Acquiring info about certificate");
            NativeLongByReference infoSize = new NativeLongByReference();
            NativeLong rv = pkcs11.C_EX_GetCertificateInfoText(session, certificate, certificateInfo, infoSize);
            Pkcs11Exception.throwIfNotOk("C_EX_GetCertificateInfoText failed", rv);

            byte[] byteCert = certificateInfo.getValue().getByteArray(0, infoSize.getValue().intValue());
            printHex("Certificate is:", byteCert);

            println("Finding key pair by certificate");
            KeyPair keyPair = Pkcs11Operations.findKeyPairByCertificateValue(pkcs11, session, certificateValue);

            byte[] digestInfo = computeDigestInfo(pkcs11, session);

            signVerify(pkcs11, session, digestInfo, keyPair);

            encryptDecrypt(pkcs11, session, keyPair);

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            NativeLong rv = pkcs11.C_EX_FreeBuffer(certificateInfo.getValue());
            checkIfNotOk("C_EX_FreeBuffer failed", rv);

            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }

    private static byte[] computeDigestInfo(Pkcs11 pkcs11, NativeLong session) throws Pkcs11Exception, IOException {
        println("\nInitializing digest function");
        NativeLong rv = pkcs11.C_DigestInit(session, new CK_MECHANISM(CKM_SHA256, null, 0));
        Pkcs11Exception.throwIfNotOk("C_DigestInit failed", rv);

        println("Getting digest size");
        NativeLongByReference digestSize = new NativeLongByReference();
        rv = pkcs11.C_Digest(session, DATA_TO_SIGN, new NativeLong(DATA_TO_SIGN.length), null, digestSize);
        Pkcs11Exception.throwIfNotOk("C_Digest failed", rv);

        println("Calculating digest");
        byte[] digest = new byte[digestSize.getValue().intValue()];
        rv = pkcs11.C_Digest(session, DATA_TO_SIGN, new NativeLong(DATA_TO_SIGN.length), digest, digestSize);
        Pkcs11Exception.throwIfNotOk("C_Digest failed", rv);

        printHex("Digest is:", digest);

        byte[] digestInfoEncoded = new DigestInfo(DigestAlgorithm.SHA256.getAlgorithmIdentifier(), digest).getEncoded();

        printHex("DigestInfo is:", digestInfoEncoded);
        println("Digest has been completed.");

        return digestInfoEncoded;
    }

    private static void signVerify(Pkcs11 pkcs11, NativeLong session, byte[] digestInfo, KeyPair keyPair)
            throws Pkcs11Exception {
        println("\nInitializing sign function");
        NativeLong rv = pkcs11.C_SignInit(session, new CK_MECHANISM(CKM_RSA_PKCS, null, 0), keyPair.privateKey);
        Pkcs11Exception.throwIfNotOk("C_SignInit failed", rv);

        println("Getting size for signature");
        NativeLongByReference signatureSize = new NativeLongByReference();
        rv = pkcs11.C_Sign(session, digestInfo, new NativeLong(digestInfo.length), null, signatureSize);
        Pkcs11Exception.throwIfNotOk("C_Sign failed", rv);

        println("Signing data");
        byte[] signature = new byte[signatureSize.getValue().intValue()];
        rv = pkcs11.C_Sign(session, digestInfo, new NativeLong(digestInfo.length), signature, signatureSize);
        Pkcs11Exception.throwIfNotOk("C_Sign failed", rv);

        printHex("Signature is:", signature);
        println("Data has been signed successfully.");

        println("\nInitializing verify function");
        rv = pkcs11.C_VerifyInit(session, new CK_MECHANISM(CKM_RSA_PKCS, null, 0), keyPair.publicKey);
        Pkcs11Exception.throwIfNotOk("C_VerifyInit failed", rv);

        println("Verifying signature");
        rv = pkcs11.C_Verify(
                session, digestInfo, new NativeLong(digestInfo.length), signature, signatureSize.getValue());
        Pkcs11Exception.throwIfNotOk("C_Verify failed", rv);

        println("Verifying has been completed successfully.");
    }

    private static void encryptDecrypt(Pkcs11 pkcs11, NativeLong session, KeyPair keyPair)
            throws Pkcs11Exception {
        println("\nInitializing encryption");
        NativeLong rv = pkcs11.C_EncryptInit(session, new CK_MECHANISM(CKM_RSA_PKCS, null, 0), keyPair.publicKey);
        Pkcs11Exception.throwIfNotOk("C_EncryptInit failed", rv);

        println("Getting size of encrypted data");
        NativeLongByReference encryptedDataSize = new NativeLongByReference();
        rv = pkcs11.C_Encrypt(session, DATA_TO_ENCRYPT, new NativeLong(DATA_TO_ENCRYPT.length), null,
                encryptedDataSize);
        Pkcs11Exception.throwIfNotOk("C_Encrypt failed", rv);

        println("Encrypting data");
        byte[] encryptedData = new byte[encryptedDataSize.getValue().intValue()];
        rv = pkcs11.C_Encrypt(session, DATA_TO_ENCRYPT, new NativeLong(DATA_TO_ENCRYPT.length), encryptedData,
                encryptedDataSize);
        Pkcs11Exception.throwIfNotOk("C_Encrypt failed", rv);

        printHex("Encrypted data is:", encryptedData);
        println("Encryption has been completed successfully.");

        println("\nInitializing decryption");
        rv = pkcs11.C_DecryptInit(session, new CK_MECHANISM(CKM_RSA_PKCS, null, 0), keyPair.privateKey);
        Pkcs11Exception.throwIfNotOk("C_DecryptInit failed", rv);

        println("Getting size of decrypted data");
        NativeLongByReference decryptedDataSize = new NativeLongByReference();
        rv = pkcs11.C_Decrypt(session, encryptedData, new NativeLong(encryptedData.length), null,
                decryptedDataSize);
        Pkcs11Exception.throwIfNotOk("C_Decrypt failed", rv);

        println("Decrypting data");
        byte[] decryptedData = new byte[decryptedDataSize.getValue().intValue()];
        rv = pkcs11.C_Decrypt(session, encryptedData, new NativeLong(encryptedData.length), decryptedData,
                decryptedDataSize);
        Pkcs11Exception.throwIfNotOk("C_Decrypt failed", rv);

        printHex("Original data is:", DATA_TO_ENCRYPT);
        printHex("Decrypted data is:", decryptedData);
        if (!Arrays.equals(DATA_TO_ENCRYPT, decryptedData))
            throw new RuntimeException("Decrypted data does not match original");

        println("Decryption has been completed successfully.");
    }
}
