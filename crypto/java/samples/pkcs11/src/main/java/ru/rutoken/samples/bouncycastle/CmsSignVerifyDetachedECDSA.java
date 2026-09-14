/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle;

import com.sun.jna.NativeLong;

import org.bouncycastle.cert.X509CertificateHolder;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.CreateKeyPairAndCertificateECDSA_SECP256K1;
import ru.rutoken.samples.CreateKeyPairAndCertificateECDSA_SECP256R1;
import ru.rutoken.samples.CreateKeyPairAndCertificateECDSA_SECP384R1;
import ru.rutoken.samples.CreateKeyPairAndCertificateECDSA_SECP521R1;
import ru.rutoken.samples.bouncycastle.cmsoperations.CmsOperations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;
import ru.rutoken.samples.utils.GostDemoCA;

import java.util.ArrayList;
import java.util.List;

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

/**
 * Sample of creating attached CMS signature and verifying it via Bouncy Castle. Expects ECDSA key pair with secp256k1
 * curve and certificate on token by default, you should run {@link CreateKeyPairAndCertificateECDSA_SECP256K1} sample
 * to create them.
 */
public class CmsSignVerifyDetachedECDSA {
    /**
     * Template for finding certificate
     */
    private static final CK_ATTRIBUTE[] certificateTemplate;
    /**
     * Specifies the identifier of the key pair used in this sample. ECDSA key pair with secp256k1 curve is used by
     * default, but it can be replaced with ECDSA key pair with secp256r1, secp384r1 or secp521r1 curves.
     *
     * @see CreateKeyPairAndCertificateECDSA_SECP256K1#KEY_PAIR_ID
     * @see CreateKeyPairAndCertificateECDSA_SECP256R1#KEY_PAIR_ID
     * @see CreateKeyPairAndCertificateECDSA_SECP384R1#KEY_PAIR_ID
     * @see CreateKeyPairAndCertificateECDSA_SECP521R1#KEY_PAIR_ID
     */
    private static final byte[] ECDSA_KEY_PAIR_ID = CreateKeyPairAndCertificateECDSA_SECP256K1.KEY_PAIR_ID;

    private static final byte[] DATA_TO_SIGN = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[2].setAttr(CKA_ID, ECDSA_KEY_PAIR_ID); // Certificate ID
        certificateTemplate[3].setAttr(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
    }

    public static void main(String[] args) {
        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        try {
            CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);
            println("Printing info about all certificates:");
            Pkcs11Operations.printAllCertificatesInfo(pkcs11, session);

            // Side A signs data into detached CMS using key pair on Rutoken device.
            // You can get certificate from some database, we'll get it from the token for simplicity.
            println("Finding signer certificate");
            byte[] signerCertificateValue = Pkcs11Operations.getFirstCertificateValue(
                    pkcs11, session, certificateTemplate);
            printString("Certificate value in PEM:", certificateToPem(signerCertificateValue));

            NativeLong signerPrivateKey = Pkcs11Operations.findPrivateKeyByCertificateValue(
                    pkcs11, session, signerCertificateValue);
            printHex("Data to sign:", DATA_TO_SIGN);

            println("Creating detached CMS signature via Bouncy Castle");
            X509CertificateHolder signerCertificateHolder = new X509CertificateHolder(signerCertificateValue);
            // You can specify digest algorithm used with ECDSA here (see SignAlgorithm class)
            byte[] detachedCmsSignature = CmsOperations.signDetached(DATA_TO_SIGN, session.longValue(),
                    signerPrivateKey.longValue(), SignAlgorithm.ECDSA_SHA256, signerCertificateHolder);
            printString("Detached CMS signature in PEM is:", cmsToPem(detachedCmsSignature));

            // Side B trusts Certificate Authority that signed Side A's certificate;
            // Side B verifies detached CMS that has been signed by Side A
            println("Verifying detached CMS signature via Bouncy Castle");
            // You should fill trustedCertificates with your business system's trusted root certs and
            // intermediateCertificates with known intermediate certificates (e.g. from user's system certificate store)
            List<X509CertificateHolder> trustedCertificates = new ArrayList<>();
            // For simplicity, we trust the Certification Authority that signed signer's certificate
            trustedCertificates.add(new X509CertificateHolder(GostDemoCA.getRootCertificate()));
            // For simplicity, we assume that signer certificate is signed directly by trusted CA,
            // therefore we don't need any intermediate certificates
            List<X509CertificateHolder> intermediateCertificates = new ArrayList<>();
            boolean isSignatureValid = CmsOperations.verifyDetached(DATA_TO_SIGN, detachedCmsSignature,
                    trustedCertificates, intermediateCertificates);
            if (!isSignatureValid)
                throw new RuntimeException("Detached CMS signature is invalid");
            println("Detached CMS signature is valid");

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }
}
