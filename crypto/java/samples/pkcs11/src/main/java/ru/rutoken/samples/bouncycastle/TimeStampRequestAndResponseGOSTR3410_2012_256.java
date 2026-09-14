/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;

import ru.rutoken.samples.utils.TimeStampUtil;

import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.TimeStampUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * This sample creates TimeStamp request using signed CMS. Then request is sent to TSA server. When the response is
 * received it is validated and its signature is verified. Then the TimeStamp token is added to initial CMS.
 * <p>
 * You should create file with CMS in PEM format. CMS could be created with
 * {@link CmsSignVerifyAttachedGOSTR3410_2012_256} sample.
 * You should input the TSA server URL and provide TSA chain certificates to verify TimeStampResponse signature.
 *
 * @see TimeStampUtil#verifyAttachedTimeStampResponseSignature for more information.
 */
public class TimeStampRequestAndResponseGOSTR3410_2012_256 {
    private static final String TSA_URL = TODO("Insert TSA server URL (in form http:// or https://)");
    private static final String CMS_FILE =
            TODO("Insert path to file with CMS in PEM format (for example, \"path/to/cms.pem\")");
    private static final String TSA_TRUSTED_CERTIFICATE_PATH =
            TODO("Insert path to file with TSA trusted certificate (for example, \"path/to/tsa_certificate.cer\"");

    public static void main(String[] args) {
        try {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);

            CMSSignedData cms = readCmsFromFile(CMS_FILE);
            printString("Original CMS signature in PEM is:", cmsToPem(cms.getEncoded()));

            TimeStampRequest timeStampRequest = makeTimeStampRequest(cms);
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

            cms = addTimeStampTokenToCms(timeStampResponse, cms);
            printString("CMS signature with TimeStamp token in PEM is:", cmsToPem(cms.getEncoded()));

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        }
    }
}
