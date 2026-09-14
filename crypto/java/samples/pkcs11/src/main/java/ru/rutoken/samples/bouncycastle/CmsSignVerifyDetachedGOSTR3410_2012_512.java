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
import ru.rutoken.samples.CreateKeyPairAndCertificateGOSTR3410_2012_512;
import ru.rutoken.samples.bouncycastle.cmsoperations.CmsOperations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;
import ru.rutoken.samples.utils.GostDemoCA;

import java.util.ArrayList;
import java.util.List;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of creating detached CMS signature and verifying it via Bouncy Castle.
 * Expects GOST R 34.10-2012 (512 bits) key and certificate on token, you should run
 * {@link CreateKeyPairAndCertificateGOSTR3410_2012_512} sample to create them.
 */
public class CmsSignVerifyDetachedGOSTR3410_2012_512 {
    /**
     * Template for finding certificate
     */
    private static final CK_ATTRIBUTE[] certificateTemplate;
    private static final byte[] DATA_TO_SIGN = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[2].setAttr(CKA_ID,
                CreateKeyPairAndCertificateGOSTR3410_2012_512.KEY_PAIR_ID); // Certificate ID
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

            byte[] detachedCmsSignature = CmsOperations.signDetached(DATA_TO_SIGN, session.longValue(),
                    signerPrivateKey.longValue(), SignAlgorithm.GOSTR3410_2012_512, signerCertificateHolder);
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
            boolean isSignatureValid = CmsOperations.verifyDetached(
                    DATA_TO_SIGN, detachedCmsSignature, trustedCertificates, intermediateCertificates);
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
