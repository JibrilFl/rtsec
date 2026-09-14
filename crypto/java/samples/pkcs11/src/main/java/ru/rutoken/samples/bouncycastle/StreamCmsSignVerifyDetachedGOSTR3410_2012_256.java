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
import ru.rutoken.samples.CreateKeyPairAndCertificateGOSTR3410_2012_256;
import ru.rutoken.samples.bouncycastle.cmsoperations.CmsOperations;
import ru.rutoken.samples.bouncycastle.cmsoperations.StreamCmsSigner;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;
import ru.rutoken.samples.utils.GostDemoCA;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of creating detached stream CMS signature and verifying it via Bouncy Castle.
 * Expects GOST R 34.10-2012 (256 bits) key and certificate on token, you should run
 * {@link CreateKeyPairAndCertificateGOSTR3410_2012_256} sample to create them.
 */
public class StreamCmsSignVerifyDetachedGOSTR3410_2012_256 {
    /**
     * Template for finding certificate
     */
    private static final CK_ATTRIBUTE[] certificateTemplate;
    private static final byte[] DATA_TO_SIGN = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[2].setAttr(CKA_ID, CreateKeyPairAndCertificateGOSTR3410_2012_256.KEY_PAIR_ID);
        certificateTemplate[3].setAttr(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
    }

    public static void main(String[] args) {
        final Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        final NativeLong session = new NativeLong(CK_INVALID_HANDLE);

        try {
            CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);
            println("Printing info about all certificates:");
            Pkcs11Operations.printAllCertificatesInfo(pkcs11, session);

            // Side A signs data into detached CMS using key pair on Rutoken device from
            // CreateKeyPairAndCertificateGOSTR3410_2012_256 sample
            // You can get certificate from some database, we'll get it from the token for simplicity
            println("Finding signer certificate");
            final byte[] signerCertificateValue = Pkcs11Operations.getFirstCertificateValue(pkcs11, session,
                    certificateTemplate);
            printString("Certificate value in PEM:", certificateToPem(signerCertificateValue));

            final NativeLong signerPrivateKey = Pkcs11Operations.findPrivateKeyByCertificateValue(pkcs11, session,
                    signerCertificateValue);

            final List<byte[]> chunks = splitChunks(DATA_TO_SIGN);
            println("Data chunks to sign:");
            for (int i = 0; i < chunks.size(); i++)
                printHex("Chunk " + (i + 1) + ":", chunks.get(i));

            println("Creating detached stream CMS signature via Bouncy Castle");
            final X509CertificateHolder signerCertificateHolder = new X509CertificateHolder(signerCertificateValue);
            final StreamCmsSigner signer = new StreamCmsSigner(SignAlgorithm.GOSTR3410_2012_256,
                    session.longValue(), signerPrivateKey.longValue());

            try (OutputStream stream = signer.openDataStream(signerCertificateHolder, false)) {
                for (byte[] chunk : chunks)
                    stream.write(chunk);
            }

            final byte[] detachedCmsSignature = signer.getSignature();
            printString("Detached stream CMS signature in PEM is:", cmsToPem(detachedCmsSignature));

            // Side B trusts Certificate Authority that signed Side A's certificate;
            // Side B verifies detached CMS that has been signed by Side A
            println("Verifying detached stream CMS signature via Bouncy Castle");
            // You should fill trustedCertificates with your business system's trusted root certs and
            // intermediateCertificates with known intermediate certificates (e.g. from user's system certificate store)
            final List<X509CertificateHolder> trustedCertificates = new ArrayList<>();
            // For simplicity, we trust the Certification Authority that signed signer's certificate
            trustedCertificates.add(new X509CertificateHolder(GostDemoCA.getRootCertificate()));
            // For simplicity, we assume that signer certificate is signed directly by trusted CA,
            // therefore we don't need any intermediate certificates
            final List<X509CertificateHolder> intermediateCertificates = new ArrayList<>();

            final boolean isSignatureValid = CmsOperations.verifyDetached(DATA_TO_SIGN, detachedCmsSignature,
                    trustedCertificates, intermediateCertificates);
            if (!isSignatureValid)
                throw new RuntimeException("Detached stream CMS signature is invalid");
            println("Detached stream CMS signature is valid");

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }

    private static List<byte[]> splitChunks(byte[] data) {
        final List<byte[]> result = new ArrayList<>();
        result.add(Arrays.copyOfRange(data, 0, data.length / 2));
        result.add(Arrays.copyOfRange(data, data.length / 2, data.length));
        return result;
    }
}
