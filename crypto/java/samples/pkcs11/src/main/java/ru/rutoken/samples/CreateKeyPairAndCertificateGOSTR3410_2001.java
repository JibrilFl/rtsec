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
import ru.rutoken.pkcs11jna.CK_DATE;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.utils.GostDemoCA;

import java.time.Period;
import java.time.ZonedDateTime;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.pkcs11utils.Constants.ATTR_CRYPTO_PRO_A_GOSTR3410_2001;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of generating GOST R 34.10-2001 key pair and importing corresponding certificate.
 */
public class CreateKeyPairAndCertificateGOSTR3410_2001 {
    /**
     * Template for public key generation
     */
    private final static CK_ATTRIBUTE[] publicKeyTemplate;
    /**
     * Template for private key generation
     */
    private final static CK_ATTRIBUTE[] privateKeyTemplate;
    /**
     * Start date of private key validity period
     */
    private final static ZonedDateTime privateKeyValidityNotBefore = ZonedDateTime.now();
    /**
     * End date of private key validity period
     */
    private final static ZonedDateTime privateKeyValidityNotAfter = privateKeyValidityNotBefore.plus(Period.ofYears(3));
    /**
     * By the convention key pair ID should be the same for private and public keys and corresponding certificate.
     * Lots of software rely on this, so we strongly recommend following this convention.
     */
    public static byte[] KEY_PAIR_ID = "Sample GOST R 34.10-2001 key pair (Aktiv Co.)".getBytes();

    static {
        publicKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(7);
        publicKeyTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
        publicKeyTemplate[1].setAttr(CKA_LABEL, "Sample GOST R 34.10-2001 Public Key (Aktiv Co.)");
        publicKeyTemplate[2].setAttr(CKA_ID, KEY_PAIR_ID);
        publicKeyTemplate[3].setAttr(CKA_KEY_TYPE, CKK_GOSTR3410); // Key type - GOST R 34.10-2001
        publicKeyTemplate[4].setAttr(CKA_TOKEN, true); // Key is stored on a token
        publicKeyTemplate[5].setAttr(CKA_PRIVATE, false); // Accessible without authentication
        publicKeyTemplate[6].setAttr(CKA_GOSTR3410_PARAMS,
                ATTR_CRYPTO_PRO_A_GOSTR3410_2001); // Parameters of GOST R 34.10-2001 algorithm

        privateKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(10);
        privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
        privateKeyTemplate[1].setAttr(CKA_LABEL, "Sample GOST R 34.10-2001 Private Key (Aktiv Co.)");
        privateKeyTemplate[2].setAttr(CKA_ID, KEY_PAIR_ID);
        privateKeyTemplate[3].setAttr(CKA_KEY_TYPE, CKK_GOSTR3410); // Key type - GOST R 34.10-2001
        privateKeyTemplate[4].setAttr(CKA_TOKEN, true); // Key is stored on a token
        privateKeyTemplate[5].setAttr(CKA_PRIVATE, true); // Accessible only after authentication
        privateKeyTemplate[6].setAttr(CKA_DERIVE, true); // Key supports key exchange (VKO)
        privateKeyTemplate[7].setAttr(CKA_GOSTR3410_PARAMS,
                ATTR_CRYPTO_PRO_A_GOSTR3410_2001); // Parameters of GOST R 34.10-2001 algorithm
        // Setting private key validity period
        CK_DATE startDate = toCkDate(privateKeyValidityNotBefore);
        CK_DATE endDate = toCkDate(privateKeyValidityNotAfter);
        privateKeyTemplate[8].setAttr(CKA_START_DATE, startDate.getPointer(), startDate.size());
        privateKeyTemplate[9].setAttr(CKA_END_DATE, endDate.getPointer(), endDate.size());
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
                    new CK_MECHANISM(CKM_GOSTR3410_KEY_PAIR_GEN, null, 0),
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
            certificateTemplate[3].setAttr(CKA_ID, KEY_PAIR_ID); // Certificate ID
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
