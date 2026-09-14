/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.ptr.PointerByReference;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_VENDOR_BUFFER;
import ru.rutoken.pkcs11jna.CK_VENDOR_X509_STORE;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.pkcs11jna.RtPkcs11Constants.*;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of rtpkcs11ecp PKI extensions usage via JNA with GOST R 34.10-2012 (256 bits) key pair.
 * Expects key pair and certificate on token, you should run
 * {@link CreateKeyPairAndCertificateGOSTR3410_2012_256} sample to create them.
 */
public class PkiExtensionsGOSTR3410_2012_256 {
    /**
     * Template for finding certificate
     */
    private final static CK_ATTRIBUTE[] certificateTemplate;

    private final static byte[] DATA_TO_SIGN = {'1', '2', '3', '3', '2', '1'};

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[2].setAttr(CKA_ID, CreateKeyPairAndCertificateGOSTR3410_2012_256.KEY_PAIR_ID);
        certificateTemplate[3].setAttr(CKA_PRIVATE, false); // Accessible without authentication
    }

    public static void main(String[] args) {
        RtPkcs11 pkcs11 = RtPkcs11Library.getPkcs11ExtendedInterface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);

        PointerByReference signature = new PointerByReference();
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

            println("Finding private key by certificate");
            NativeLong privateKey = Pkcs11Operations.findPrivateKeyByCertificateValue(pkcs11, session,
                    certificateValue);

            println("PKCS7 (CMS) signing");
            NativeLongByReference signatureLen = new NativeLongByReference();
            rv = pkcs11.C_EX_PKCS7Sign(session, DATA_TO_SIGN, new NativeLong(DATA_TO_SIGN.length),
                    certificate, signature, signatureLen, privateKey, null,
                    new NativeLong(0), new NativeLong(0));
            Pkcs11Exception.throwIfNotOk("C_EX_PKCS7Sign failed", rv);
            println("Data has been signed successfully");

            byte[] byteSignature = signature.getValue().getByteArray(0, signatureLen.getValue().intValue());
            printHex("Signed data is:", byteSignature);

            verifyCmsUsingCertificateAsTrustedCertificate(pkcs11, session, certificateValue, signature.getValue(),
                    signatureLen.getValue());

            verifyCmsWithoutTrustedCertificates(pkcs11, session, signature.getValue(), signatureLen.getValue());

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            NativeLong rv = pkcs11.C_EX_FreeBuffer(signature.getValue());
            checkIfNotOk("C_EX_FreeBuffer failed", rv);

            rv = pkcs11.C_EX_FreeBuffer(certificateInfo.getValue());
            checkIfNotOk("C_EX_FreeBuffer failed", rv);

            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }

    public static void verifyCmsUsingCertificateAsTrustedCertificate(RtPkcs11 pkcs11, NativeLong session,
                                                                     byte[] signerCertificate,
                                                                     Pointer signature, NativeLong signatureLen)
            throws Pkcs11Exception {
        println("Verifying PKCS7 signature using signer certificate as trusted certificate");
        CK_VENDOR_BUFFER.ByReference[] trustedCerts =
                (CK_VENDOR_BUFFER.ByReference[]) new CK_VENDOR_BUFFER.ByReference(signerCertificate).toArray(1);
        CK_VENDOR_X509_STORE storeWithTrustedSignerCert = new CK_VENDOR_X509_STORE(trustedCerts, null, null);
        NativeLong rv = pkcs11.C_EX_PKCS7VerifyInit(session, signature, signatureLen, storeWithTrustedSignerCert,
                new NativeLong(OPTIONAL_CRL_CHECK),
                new NativeLong(CKF_VENDOR_ALLOW_PARTIAL_CHAINS));
        Pkcs11Exception.throwIfNotOk("C_EX_PKCS7VerifyInit failed", rv);

        PointerByReference dataRef = new PointerByReference();
        NativeLongByReference dataSize = new NativeLongByReference();
        PointerByReference signerCertificatesRef = new PointerByReference();
        NativeLongByReference pulSignerCertificatesCount = new NativeLongByReference();
        try {
            rv = pkcs11.C_EX_PKCS7Verify(session, dataRef, dataSize,
                    signerCertificatesRef, pulSignerCertificatesCount);
            Pkcs11Exception.throwIfNotOk("C_EX_PKCS7Verify failed", rv);
            println("Data has been verified successfully");

            println("Printing C_EX_PKCS7Verify results:");
            Pointer data = dataRef.getValue();
            if (data != null) {
                byte[] verifiedData = data.getByteArray(0, dataSize.getValue().intValue());
                printHex("Verified data is:", verifiedData);
            }

            Pointer signerCertificates = signerCertificatesRef.getValue();
            if (signerCertificates != null) {
                CK_VENDOR_BUFFER firstSignerCertFromVerify = new CK_VENDOR_BUFFER(signerCertificates);
                CK_VENDOR_BUFFER[] signerCertsFromVerify =
                        (CK_VENDOR_BUFFER[]) firstSignerCertFromVerify
                                .toArray(pulSignerCertificatesCount.getValue().intValue());
                for (int i = 0; i < signerCertsFromVerify.length; ++i) {
                    byte[] byteSignerCertFromVerify = signerCertsFromVerify[i]
                            .pData.getByteArray(0, signerCertsFromVerify[i].ulSize.intValue());
                    printHex("Signer certificate No " + i + ":", byteSignerCertFromVerify);
                }
            }
        } finally {
            freePkcs7VerifyResources(pkcs11, dataRef.getValue(), signerCertificatesRef.getValue(),
                    pulSignerCertificatesCount.getValue().intValue());
        }
    }

    public static void verifyCmsWithoutTrustedCertificates(RtPkcs11 pkcs11, NativeLong session,
                                                           Pointer signature, NativeLong signatureLen)
            throws Pkcs11Exception {
        println("Verifying PKCS7 signature without trusted certificates");

        CK_VENDOR_X509_STORE emptyStore = new CK_VENDOR_X509_STORE(null, null, null);
        NativeLong rv = pkcs11.C_EX_PKCS7VerifyInit(session, signature, signatureLen, emptyStore,
                new NativeLong(OPTIONAL_CRL_CHECK),
                new NativeLong(CKF_VENDOR_ALLOW_PARTIAL_CHAINS));
        Pkcs11Exception.throwIfNotOk("C_EX_PKCS7VerifyInit failed", rv);

        PointerByReference data = new PointerByReference();
        NativeLongByReference dataSize = new NativeLongByReference();
        PointerByReference signerCertificates = new PointerByReference();
        NativeLongByReference signerCertificatesCount = new NativeLongByReference();
        try {
            rv = pkcs11.C_EX_PKCS7Verify(session, data, dataSize, signerCertificates, signerCertificatesCount);
            if (!equalsPkcsRV(CKR_CERT_CHAIN_NOT_VERIFIED, rv)) {
                throw new RuntimeException("C_EX_PKCS7Verify failed, error code: " + Long.toHexString(rv.longValue())
                        + ", expected: " + Long.toHexString(CKR_CERT_CHAIN_NOT_VERIFIED));
            }
            println("Signature is valid, but as no trusted certificates have been provided, " +
                    "signer's certificate chain couldn't be verified");
        } finally {
            freePkcs7VerifyResources(pkcs11, data.getValue(), signerCertificates.getValue(),
                    signerCertificatesCount.getValue().intValue());
        }
    }

    public static void freePkcs7VerifyResources(RtPkcs11 pkcs11, Pointer data, Pointer signerCertificates,
                                                int signerCertificatesCount) {
        println("Freeing resources allocated by pkcs11ecp in C_EX_PKCS7Verify");

        if (data != null) {
            NativeLong rv = pkcs11.C_EX_FreeBuffer(data);
            checkIfNotOk("C_EX_FreeBuffer failed", rv);
        }

        if (signerCertificates != null) {
            CK_VENDOR_BUFFER[] signerCertsFromVerify =
                    (CK_VENDOR_BUFFER[]) new CK_VENDOR_BUFFER(signerCertificates).toArray(signerCertificatesCount);
            for (CK_VENDOR_BUFFER buffer : signerCertsFromVerify) {
                NativeLong rv = pkcs11.C_EX_FreeBuffer(buffer.pData);
                checkIfNotOk("C_EX_FreeBuffer failed", rv);
            }

            NativeLong rv = pkcs11.C_EX_FreeBuffer(signerCertificates);
            checkIfNotOk("C_EX_FreeBuffer failed", rv);
        }
    }
}
