/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.utils;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import ru.rutoken.samples.bouncycastle.cmsoperations.CmsOperations;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public final class TimeStampUtil {
    private TimeStampUtil() {
    }

    public static TimeStampRequest makeTimeStampRequest(CMSSignedData cms) throws NoSuchAlgorithmException {
        Collection<SignerInformation> signerInfos = cms.getSignerInfos().getSigners();
        if (signerInfos.isEmpty())
            throw new IllegalArgumentException("No signers found.");
        if (signerInfos.size() != 1)
            throw new IllegalArgumentException("More than 1 signer found.");

        SignerInformation signerInformation = signerInfos.iterator().next();
        byte[] hashFromSignature = MessageDigest
                .getInstance(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.toString())
                .digest(signerInformation.getSignature());

        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        return generator.generate(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, hashFromSignature);
    }

    public static TimeStampResponse getTimeStampResponseFromServer(URL serverUrl, TimeStampRequest timeStampRequest)
            throws IOException, TSPException {
        HttpURLConnection connection = (HttpURLConnection) serverUrl.openConnection();
        try {
            byte[] request = timeStampRequest.getEncoded();

            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-type", "application/timestamp-query");
            connection.setRequestProperty("Content-length", String.valueOf(request.length));

            try (OutputStream outStream = connection.getOutputStream()) {
                outStream.write(request);
            }

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK)
                throw new IOException("Received HTTP error: " + connection.getResponseCode()
                        + " - " + connection.getResponseMessage());

            try (InputStream inStream = connection.getInputStream()) {
                TimeStampResp response = TimeStampResp.getInstance(new ASN1InputStream(inStream).readObject());
                return new TimeStampResponse(response);
            }
        } finally {
            connection.disconnect();
        }
    }

    public static void validate(TimeStampResponse timeStampResponse, TimeStampRequest timeStampRequest)
            throws TSPException {
        timeStampResponse.validate(timeStampRequest);
        if (timeStampResponse.getStatus() != PKIStatus.GRANTED
                && timeStampResponse.getStatus() != PKIStatus.GRANTED_WITH_MODS)
            throw new RuntimeException("TimeStamp response status check failed: "
                    + timeStampResponse.getStatusString());
    }

    public static CMSSignedData addTimeStampTokenToCms(TimeStampResponse timeStampResponse, CMSSignedData cms)
            throws IOException {
        ASN1InputStream asn1InputStream = new ASN1InputStream(timeStampResponse.getTimeStampToken().getEncoded());
        DERSet ds = new DERSet(asn1InputStream.readObject());

        Attribute timestampTokenAttr = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, ds);
        ASN1EncodableVector derVector = new ASN1EncodableVector();
        derVector.add(timestampTokenAttr);
        AttributeTable attributeTable = new AttributeTable(derVector);

        Collection<SignerInformation> signerInfos = cms.getSignerInfos().getSigners();
        SignerInformation signerInformation = SignerInformation.replaceUnsignedAttributes(signerInfos.iterator().next(),
                attributeTable);
        Collection<SignerInformation> replacingSignerInfos = Collections.singletonList(signerInformation);
        SignerInformationStore signerInformationStore = new SignerInformationStore(replacingSignerInfos);

        return CMSSignedData.replaceSigners(cms, signerInformationStore);
    }

    public static void verifyAttachedTimeStampResponseSignature(TimeStampResponse timeStampResponse,
                                                                List<X509CertificateHolder> trustedCertificates,
                                                                List<X509CertificateHolder> intermediateCertificates,
                                                                List<X509CertificateHolder> additionalCertificates) {
        CMSSignedData responseCms = timeStampResponse.getTimeStampToken().toCMSSignedData();

        boolean isSignatureValid = CmsOperations.verifyAttached(responseCms, trustedCertificates,
                intermediateCertificates, additionalCertificates);
        if (!isSignatureValid)
            throw new RuntimeException("Attached CMS signature is invalid");
    }
}
