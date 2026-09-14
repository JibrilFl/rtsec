/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.bouncycastle.utils.RtPkcs10RequestUtils;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11TokenUtils;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.Pkcs11TokenUtils;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;
import ru.rutoken.samples.utils.GostDemoCA;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_CATEGORY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CERTIFICATE_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_DERIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_EC_PARAMS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_KEY_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_LABEL;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_PRIVATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_TOKEN;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_VALUE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKC_X_509;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_EC;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_EC_KEY_PAIR_GEN;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PRIVATE_KEY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PUBLIC_KEY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_CERTIFICATE_CATEGORY_TOKEN_USER;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_INVALID_HANDLE;
import static ru.rutoken.samples.pkcs11utils.Constants.ATTR_ECDSA_SECP384R1;
import static ru.rutoken.samples.utils.CommonUtil.printString;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;
import static ru.rutoken.samples.utils.Util.BC_DN;
import static ru.rutoken.samples.utils.Util.BC_EXTS;
import static ru.rutoken.samples.utils.Util.certificateToPem;
import static ru.rutoken.samples.utils.Util.printCsr;

/**
 * Sample of generating ECDSA key pair with secp384r1 curve and importing corresponding certificate.
 */
public class CreateKeyPairAndCertificateECDSA_SECP384R1 {
    /**
     * By the convention key pair ID should be the same for private and public keys and corresponding certificate.
     * Lots of software rely on this, so we strongly recommend following this convention.
     */
    public final static byte[] KEY_PAIR_ID = "Sample ECDSA secp384r1 key pair (Aktiv Co.)".getBytes();
    /**
     * Template for public key generation
     */
    private final static CK_ATTRIBUTE[] publicKeyTemplate;
    /**
     * Template for private key generation
     */
    private final static CK_ATTRIBUTE[] privateKeyTemplate;

    static {
        publicKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(7);
        publicKeyTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
        publicKeyTemplate[1].setAttr(CKA_LABEL, "Sample ECDSA secp384r1 Public Key (Aktiv Co.)");
        publicKeyTemplate[2].setAttr(CKA_ID, KEY_PAIR_ID);
        publicKeyTemplate[3].setAttr(CKA_KEY_TYPE, CKK_EC);
        publicKeyTemplate[4].setAttr(CKA_TOKEN, true); // Key is stored on a token
        publicKeyTemplate[5].setAttr(CKA_PRIVATE, false); // Accessible without authentication
        publicKeyTemplate[6].setAttr(CKA_EC_PARAMS, ATTR_ECDSA_SECP384R1);

        privateKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(7);
        privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
        privateKeyTemplate[1].setAttr(CKA_LABEL, "Sample ECDSA secp384r1 Private Key (Aktiv Co.)");
        privateKeyTemplate[2].setAttr(CKA_ID, KEY_PAIR_ID);
        privateKeyTemplate[3].setAttr(CKA_KEY_TYPE, CKK_EC);
        privateKeyTemplate[4].setAttr(CKA_TOKEN, true); // Key is stored on a token
        privateKeyTemplate[5].setAttr(CKA_PRIVATE, true); // Accessible only after authentication
        privateKeyTemplate[6].setAttr(CKA_DERIVE, true); // Key supports key exchange (VKO)
    }

    public static void main(String[] args) {
        RtPkcs11 pkcs11 = RtPkcs11Library.getPkcs11ExtendedInterface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        try {
            NativeLong token = CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);

            if (!CommonPkcs11TokenUtils.isMechanismSupported(pkcs11, token, CKM_EC_KEY_PAIR_GEN))
                throw new UnsupportedOperationException("Token doesn't support the ECDSA mechanism.");

            if (!Pkcs11TokenUtils.isLongEcdsaCurvesSupported(pkcs11, token))
                throw new UnsupportedOperationException("Token doesn't support the secp384r1 and secp521r1 curves.");

            NativeLongByReference publicKey = new NativeLongByReference();
            NativeLongByReference privateKey = new NativeLongByReference();
            println("Generating key pair");
            NativeLong rv = pkcs11.C_GenerateKeyPair(session,
                    new CK_MECHANISM(CKM_EC_KEY_PAIR_GEN, null, 0),
                    publicKeyTemplate, new NativeLong(publicKeyTemplate.length),
                    privateKeyTemplate, new NativeLong(privateKeyTemplate.length), publicKey, privateKey);
            Pkcs11Exception.throwIfNotOk("C_GenerateKeyPair failed", rv);

            println("Creating certificate signing request (CSR) via Bouncy Castle");
            // You can specify digest algorithm used with ECDSA here (see SignAlgorithm enum class)
            byte[] csrBytes = RtPkcs10RequestUtils.createCsrOnEcdsaKeys(pkcs11, session, publicKey.getValue(),
                    privateKey.getValue(), SignAlgorithm.ECDSA_SHA256, BC_DN, BC_EXTS);
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
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }
}
