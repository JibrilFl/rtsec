/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.ptr.PointerByReference;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.utils.GostDemoCA;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of generating RSA key pair and importing corresponding certificate.
 */
public class CreateKeyPairAndCertificateRSA {
    /**
     * Value of CKA_MODULUS_BITS attribute.
     * For example, to generate RSA-4096 set this value to 4096.
     */
    private static final int MODULUS_BITS_LENGTH = 2048;
    /**
     * Template for public key generation
     */
    private final static CK_ATTRIBUTE[] publicKeyTemplate;
    /**
     * Template for private key generation
     */
    private final static CK_ATTRIBUTE[] privateKeyTemplate;
    /**
     * By the convention key pair ID should be the same for private and public keys and corresponding certificate.
     * Lots of software rely on this, so we strongly recommend following this convention.
     */
    public static byte[] KEY_PAIR_ID = "Sample RSA key pair (Aktiv Co.)".getBytes();

    static {
        publicKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(8);
        publicKeyTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
        publicKeyTemplate[1].setAttr(CKA_LABEL, "Sample RSA Public Key (Aktiv Co.)");
        publicKeyTemplate[2].setAttr(CKA_ID, KEY_PAIR_ID);
        publicKeyTemplate[3].setAttr(CKA_KEY_TYPE, CKK_RSA);
        publicKeyTemplate[4].setAttr(CKA_ENCRYPT, true); // Key supports encryption
        publicKeyTemplate[5].setAttr(CKA_TOKEN, true); // Key is stored on a token
        publicKeyTemplate[6].setAttr(CKA_PRIVATE, false); // Accessible without authentication
        publicKeyTemplate[7].setAttr(CKA_MODULUS_BITS, MODULUS_BITS_LENGTH);

        privateKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(7);
        privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
        privateKeyTemplate[1].setAttr(CKA_LABEL, "Sample RSA Private Key (Aktiv Co.)");
        privateKeyTemplate[2].setAttr(CKA_ID, KEY_PAIR_ID);
        privateKeyTemplate[3].setAttr(CKA_KEY_TYPE, CKK_RSA);
        privateKeyTemplate[4].setAttr(CKA_DECRYPT, true); // Key supports decryption
        privateKeyTemplate[5].setAttr(CKA_TOKEN, true); // Key is stored on a token
        privateKeyTemplate[6].setAttr(CKA_PRIVATE, true); // Accessible only after authentication
    }

    public static void main(String[] args) {
        RtPkcs11 pkcs11 = RtPkcs11Library.getPkcs11ExtendedInterface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        PointerByReference csr = new PointerByReference();
        try {
            CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);

            NativeLongByReference publicKey = new NativeLongByReference();
            NativeLongByReference privateKey = new NativeLongByReference();
            println("Generating key pair");
            NativeLong rv = pkcs11.C_GenerateKeyPair(session,
                    new CK_MECHANISM(CKM_RSA_PKCS_KEY_PAIR_GEN, null, 0),
                    publicKeyTemplate, new NativeLong(publicKeyTemplate.length),
                    privateKeyTemplate, new NativeLong(privateKeyTemplate.length), publicKey, privateKey);
            Pkcs11Exception.throwIfNotOk("C_GenerateKeyPair failed", rv);

            println("Creating certificate signing request (CSR)");
            NativeLongByReference csrSize = new NativeLongByReference();
            rv = pkcs11.C_EX_CreateCSR(session, publicKey.getValue(), PKCS11_DN, new NativeLong(PKCS11_DN.length),
                    csr, csrSize, privateKey.getValue(), null, new NativeLong(0), PKCS11_EXTS,
                    new NativeLong(PKCS11_EXTS.length));
            Pkcs11Exception.throwIfNotOk("C_EX_CreateCSR failed", rv);

            byte[] csrBytes = csr.getValue().getByteArray(0, csrSize.getValue().intValue());
            printCsr("CSR:", csrBytes);

            println("Issuing certificate by CSR with demo Certification Authority");
            byte[] certificate = GostDemoCA.issueCertificate(csrBytes);
            printString("Certificate value in PEM:", certificateToPem(certificate));

            // Fill in template for importing of certificate
            CK_ATTRIBUTE[] certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(7);
            certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
            certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
            certificateTemplate[2].setAttr(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
            certificateTemplate[3].setAttr(CKA_ID, KEY_PAIR_ID);  // Certificate ID
            certificateTemplate[4].setAttr(CKA_TOKEN, true); // Certificate is stored on a token
            certificateTemplate[5].setAttr(CKA_PRIVATE, false); // Accessible without authentication
            certificateTemplate[6].setAttr(CKA_VALUE, certificate); // Certificate value

            NativeLongByReference certificateHandle = new NativeLongByReference();
            println("Importing certificate");
            rv = pkcs11.C_CreateObject(session, certificateTemplate, new NativeLong(certificateTemplate.length),
                    certificateHandle);
            Pkcs11Exception.throwIfNotOk("C_CreateObject failed", rv);

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            if (csr.getValue() != null) {
                NativeLong rv = pkcs11.C_EX_FreeBuffer(csr.getValue());
                checkIfNotOk("C_EX_FreeBuffer failed", rv);
            }
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }
}
