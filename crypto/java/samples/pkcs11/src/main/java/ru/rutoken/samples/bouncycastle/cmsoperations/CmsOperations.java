/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.cmsoperations;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ru.rutoken.samples.pkcs11utils.SignAlgorithm;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Common operations with CMS
 */
public final class CmsOperations {
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private CmsOperations() {
    }

    public static byte[] encryptByKeyTransportProtocol(byte[] data, byte[] certificateValue,
                                                       ASN1ObjectIdentifier contentEncryptionAlgorithm)
            throws CertificateException, CMSException, IOException {
        return CmsEncryptor.encryptByKeyTransportProtocol(data, certificateValue, contentEncryptionAlgorithm);
    }

    public static byte[] encryptByKeyAgreeProtocol(byte[] data, byte[] certificateValue,
                                                   ASN1ObjectIdentifier keyAgreementAlgorithmOID,
                                                   ASN1ObjectIdentifier keyWrapAlgorithmOID,
                                                   ASN1ObjectIdentifier contentEncryptionAlgorithmOID)
            throws CMSException, IOException, CertificateException {
        return CmsEncryptor.encryptByKeyAgreeProtocol(data, certificateValue, keyAgreementAlgorithmOID,
                keyWrapAlgorithmOID, contentEncryptionAlgorithmOID);
    }

    public static byte[] decrypt(byte[] data, long sessionHandle, long keyHandle,
                                 List<X509Certificate> possibleRecipientsCertificates) throws CMSException {
        return new CmsDecryptor(sessionHandle).decrypt(data, keyHandle, possibleRecipientsCertificates);
    }

    public static byte[] signAttached(byte[] data, long sessionHandle, long privateKeyHandle,
                                      SignAlgorithm signAlgorithm, X509CertificateHolder signerCertificate)
            throws IOException {
        return new CmsSigner(signAlgorithm, sessionHandle, privateKeyHandle).signAttached(data, signerCertificate);
    }

    public static byte[] signDetached(byte[] data, long sessionHandle, long privateKeyHandle,
                                      SignAlgorithm signAlgorithm, X509CertificateHolder signerCertificate)
            throws IOException {
        return new CmsSigner(signAlgorithm, sessionHandle, privateKeyHandle).signDetached(data, signerCertificate);
    }

    public static byte[] signCadesBesAttached(byte[] data, long sessionHandle, long privateKeyHandle,
                                              SignAlgorithm signAlgorithm, X509CertificateHolder signerCertificate)
            throws IOException, NoSuchAlgorithmException {
        return new GostCadesBesSigner(signAlgorithm, sessionHandle, privateKeyHandle)
                .signAttached(data, signerCertificate);
    }

    public static byte[] signCadesBesDetached(byte[] data, long sessionHandle, long privateKeyHandle,
                                              SignAlgorithm signAlgorithm, X509CertificateHolder signerCertificate)
            throws IOException, NoSuchAlgorithmException {
        return new GostCadesBesSigner(signAlgorithm, sessionHandle, privateKeyHandle)
                .signDetached(data, signerCertificate);
    }

    public static boolean verifyAttached(byte[] attachedCms, List<X509CertificateHolder> trustedCertificates,
                                         List<X509CertificateHolder> intermediateCertificates) throws CMSException {
        CMSSignedData cmsSignedData = new CMSSignedData(attachedCms);
        return CmsVerifier.verifyCms(cmsSignedData, trustedCertificates, intermediateCertificates,
                Collections.emptyList());
    }

    public static boolean verifyDetached(byte[] content, byte[] detachedCms,
                                         List<X509CertificateHolder> trustedCertificates,
                                         List<X509CertificateHolder> intermediateCertificates) throws CMSException {
        CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(content), detachedCms);
        return CmsVerifier.verifyCms(cmsSignedData, trustedCertificates, intermediateCertificates,
                Collections.emptyList());
    }

    public static boolean verifyAttached(CMSSignedData attachedCms, List<X509CertificateHolder> trustedCertificates,
                                         List<X509CertificateHolder> intermediateCertificates,
                                         List<X509CertificateHolder> additionalCerts) {
        return CmsVerifier.verifyCms(attachedCms, trustedCertificates, intermediateCertificates, additionalCerts);
    }
}
