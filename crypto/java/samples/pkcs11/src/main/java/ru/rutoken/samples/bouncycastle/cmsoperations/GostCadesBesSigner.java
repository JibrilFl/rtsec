/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.cmsoperations;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ru.rutoken.samples.pkcs11utils.SignAlgorithm;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

class GostCadesBesSigner {
    private final StreamCmsSigner mStreamCmsSigner;

    GostCadesBesSigner(SignAlgorithm signAlgorithm, long sessionHandle, long privateKeyHandle) {
        mStreamCmsSigner = new StreamCmsSigner(signAlgorithm, sessionHandle, privateKeyHandle);
    }

    private static IssuerSerial getIssuerSerial(X509CertificateHolder signerCertificate) {
        X500Name issuerX500Name = signerCertificate.getIssuer();
        GeneralName generalName = new GeneralName(issuerX500Name);
        GeneralNames generalNames = new GeneralNames(generalName);
        ASN1Integer serial = new ASN1Integer(signerCertificate.getSerialNumber());
        return new IssuerSerial(generalNames, serial);
    }

    byte[] signAttached(byte[] data, X509CertificateHolder certificate) throws IOException, NoSuchAlgorithmException {
        return sign(data, certificate, true);
    }

    byte[] signDetached(byte[] data, X509CertificateHolder certificate) throws IOException, NoSuchAlgorithmException {
        return sign(data, certificate, false);
    }

    private byte[] sign(byte[] data, X509CertificateHolder signerCertificate, boolean attached)
            throws IOException, NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("GOST3411-2012-256", new BouncyCastleProvider());
        byte[] certificateDigest = messageDigest.digest(signerCertificate.getEncoded());

        SigningCertificateV2 signingCertificate = new SigningCertificateV2(
                new ESSCertIDv2(
                        new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256),
                        certificateDigest,
                        getIssuerSerial(signerCertificate)
                )
        );

        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        signedAttributes.add(new Attribute(id_aa_signingCertificateV2, new DERSet(signingCertificate)));
        AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);

        try (OutputStream stream = mStreamCmsSigner.openDataStream(signerCertificate, attached,
                new DefaultSignedAttributeTableGenerator(signedAttributesTable))) {
            stream.write(data);
        }

        return mStreamCmsSigner.getSignature();
    }
}
