/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle;

import com.sun.jna.NativeLong;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.CreateKeyPairAndCertificateGOSTR3410_2012_256;
import ru.rutoken.samples.bouncycastle.cmsoperations.CmsOperations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;
import ru.rutoken.samples.utils.TimeStampUtil;

import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.TimeStampUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * This sample creates attached CAdES-T signature using Bouncy Castle.
 * Attached CAdES-BES signature is created and TimeStamp request is generated. Then request is sent to TSA server.
 * When the response is received it is validated and its signature is verified. Then the TimeStamp token is added to
 * initial CAdES-BES signature.
 * Expects key and certificate on token, you should run {@link CreateKeyPairAndCertificateGOSTR3410_2012_256} sample
 * to create them.
 * <p>
 * You should input the TSA server URL and provide TSA chain certificates to verify TimeStampResponse signature.
 *
 * @see TimeStampUtil#verifyAttachedTimeStampResponseSignature for more information.
 */
public class CadesTSignVerifyAttachedGOSTR3410_2012_256 {
    /**
     * Template for finding GOST R 34.10-2012 (256 bits) certificate
     */
    private static final CK_ATTRIBUTE[] certificateTemplate;
    private static final byte[] DATA_TO_SIGN = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    private static final String TSA_URL = TODO("Insert TSA server URL (in form http:// or https://)");
    private static final String TSA_TRUSTED_CERTIFICATE_PATH =
            TODO("Insert path to file with TSA trusted certificate (for example, \"path/to/tsa_certificate.cer\"");

    static {
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_CERTIFICATE_TYPE, CKC_X_509);
        certificateTemplate[2].setAttr(CKA_ID, CreateKeyPairAndCertificateGOSTR3410_2012_256.KEY_PAIR_ID);
        certificateTemplate[3].setAttr(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
    }

    public static void main(String[] args) {
        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);

        try {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);

            CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);
            println("Printing info about all certificates:");
            Pkcs11Operations.printAllCertificatesInfo(pkcs11, session);

            // Side A signs data into CMS with attached content using key pair on Rutoken device
            // You can get certificate from some database, we'll get it from the token for simplicity
            println("Finding signer certificate");
            byte[] signerCertificateValue = Pkcs11Operations.getFirstCertificateValue(pkcs11, session,
                    certificateTemplate);
            printString("Certificate value in PEM:", certificateToPem(signerCertificateValue));

            NativeLong signerPrivateKey = Pkcs11Operations.findPrivateKeyByCertificateValue(pkcs11, session,
                    signerCertificateValue);

            printHex("Data to sign:", DATA_TO_SIGN);

            println("Creating CAdES-BES signature via Bouncy Castle");
            X509CertificateHolder signerCertificateHolder = new X509CertificateHolder(signerCertificateValue);
            byte[] cadesBesSignatureEncoded = CmsOperations.signCadesBesAttached(DATA_TO_SIGN, session.longValue(),
                    signerPrivateKey.longValue(), SignAlgorithm.GOSTR3410_2012_256, signerCertificateHolder);

            printString("CAdES-BES signature in PEM is:", cmsToPem(cadesBesSignatureEncoded));

            CMSSignedData cadesBesSignature = getCmsFromBytes(cadesBesSignatureEncoded);
            TimeStampRequest timeStampRequest = makeTimeStampRequest(cadesBesSignature);
            println("TimeStamp request created successfully.");

            TimeStampResponse timeStampResponse = getTimeStampResponseFromServer(new URL(TSA_URL), timeStampRequest);
            println("TimeStamp response received successfully.");

            validate(timeStampResponse, timeStampRequest);
            println("TimeStamp response validated successfully.");

            printString("TimeStamp token in PEM is:",
                    cmsToPem(timeStampResponse.getTimeStampToken().toCMSSignedData().getEncoded()));

            // Add the trusted certificates from the TSA certificate chain
            List<X509CertificateHolder> trustedCertificates = new ArrayList<>();
            trustedCertificates.add(getX509CertificateHolder(TSA_TRUSTED_CERTIFICATE_PATH));

            // Add the intermediate certificates from the TSA certificate chain
            List<X509CertificateHolder> intermediateCertificates = new ArrayList<>();

            // If TSA certificate is not included in the TimeStampToken you should provide it here
            List<X509CertificateHolder> additionalCertificates = new ArrayList<>();

            verifyAttachedTimeStampResponseSignature(timeStampResponse, trustedCertificates, intermediateCertificates,
                    additionalCertificates);
            println("TimeStamp token signature verified successfully.");

            CMSSignedData cadesTSignature = addTimeStampTokenToCms(timeStampResponse, cadesBesSignature);
            printString("CAdES-T signature in PEM is:", cmsToPem(cadesTSignature.getEncoded()));

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        }
    }
}
