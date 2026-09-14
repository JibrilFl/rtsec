/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.cmsoperations;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

import static ru.rutoken.samples.utils.Util.getX509Certificate;

class CmsEncryptor {
    private CmsEncryptor() {
    }

    static byte[] encryptByKeyTransportProtocol(byte[] data, byte[] certificateValue,
                                                ASN1ObjectIdentifier contentEncryptionAlgorithm)
            throws CertificateException, CMSException, IOException {
        JceKeyTransRecipientInfoGenerator recipientInfoGenerator =
                new JceKeyTransRecipientInfoGenerator(getX509Certificate(certificateValue));

        return createCmsEnvelopedData(data, recipientInfoGenerator, contentEncryptionAlgorithm).getEncoded();
    }

    static byte[] encryptByKeyAgreeProtocol(byte[] data, byte[] certificateValue,
                                            ASN1ObjectIdentifier keyAgreementAlgorithmOID,
                                            ASN1ObjectIdentifier keyWrapAlgorithmOID,
                                            ASN1ObjectIdentifier contentEncryptionAlgorithmOID)
            throws CertificateException, CMSException, IOException {
        X509CertificateHolder recipientCertificateHolder = new X509CertificateHolder(certificateValue);
        SubjectPublicKeyInfo recipientPublicKeyInfo = recipientCertificateHolder.getSubjectPublicKeyInfo();
        ASN1ObjectIdentifier ecCurveOID =
                ASN1ObjectIdentifier.getInstance(recipientPublicKeyInfo.getAlgorithm().getParameters());

        KeyPairGenerator ecKeyPairGenerator;
        try {
            ecKeyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            ecKeyPairGenerator.initialize(new ECGenParameterSpec(SECNamedCurves.getName(ecCurveOID)),
                    new SecureRandom());
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new CMSException("Failed to initialize the generator for ephemeral EC key pair.", e);
        }
        KeyPair ephemeralEcKeyPair = ecKeyPairGenerator.generateKeyPair();

        JceKeyAgreeRecipientInfoGenerator recipientInfoGenerator =
                new JceKeyAgreeRecipientInfoGenerator(keyAgreementAlgorithmOID, ephemeralEcKeyPair.getPrivate(),
                        ephemeralEcKeyPair.getPublic(), keyWrapAlgorithmOID)
                        .addRecipient(getX509Certificate(recipientCertificateHolder));

        return createCmsEnvelopedData(data, recipientInfoGenerator, contentEncryptionAlgorithmOID).getEncoded();
    }

    private static CMSEnvelopedData createCmsEnvelopedData(byte[] data, RecipientInfoGenerator recipientGenerator,
                                                           ASN1ObjectIdentifier contentEncryptionAlgorithmOID)
            throws CMSException {
        CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
        cmsEnvelopedDataGenerator.addRecipientInfoGenerator(recipientGenerator);
        OutputEncryptor contentEncryptor = new JceCMSContentEncryptorBuilder(contentEncryptionAlgorithmOID).setProvider(
                BouncyCastleProvider.PROVIDER_NAME).build();

        return cmsEnvelopedDataGenerator.generate(new CMSProcessableByteArray(data), contentEncryptor);
    }
}
