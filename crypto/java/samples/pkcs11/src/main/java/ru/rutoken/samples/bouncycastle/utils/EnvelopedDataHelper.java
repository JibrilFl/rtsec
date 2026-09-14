/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.utils;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ecc.ECCCMSSharedInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.util.Pack;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import static org.bouncycastle.cms.CMSAlgorithm.AES128_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.AES128_WRAP;
import static org.bouncycastle.cms.CMSAlgorithm.AES192_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.AES192_WRAP;
import static org.bouncycastle.cms.CMSAlgorithm.AES256_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.AES256_WRAP;
import static org.bouncycastle.cms.CMSAlgorithm.DES_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.DES_EDE3_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.ECDH_SHA1KDF;
import static org.bouncycastle.cms.CMSAlgorithm.ECDH_SHA224KDF;
import static org.bouncycastle.cms.CMSAlgorithm.ECDH_SHA256KDF;
import static org.bouncycastle.cms.CMSAlgorithm.ECDH_SHA384KDF;
import static org.bouncycastle.cms.CMSAlgorithm.ECDH_SHA512KDF;
import static org.bouncycastle.cms.CMSAlgorithm.RC2_CBC;

public final class EnvelopedDataHelper {
    private final static Map<ASN1ObjectIdentifier, String> BASE_CIPHER_NAMES = new HashMap<>();
    private final static Map<ASN1ObjectIdentifier, String> WRAPPING_CIPHER_NAMES = new HashMap<>();
    private final static Map<ASN1ObjectIdentifier, String> ENCRYPTION_CIPHER_NAMES = new HashMap<>();

    static {
        BASE_CIPHER_NAMES.put(DES_CBC, "DES");
        BASE_CIPHER_NAMES.put(RC2_CBC, "RC2");
        BASE_CIPHER_NAMES.put(DES_EDE3_CBC, "DESEDE");
        BASE_CIPHER_NAMES.put(AES128_CBC, "AES");
        BASE_CIPHER_NAMES.put(AES192_CBC, "AES");
        BASE_CIPHER_NAMES.put(AES256_CBC, "AES");

        BASE_CIPHER_NAMES.put(AES128_WRAP, "AES");
        BASE_CIPHER_NAMES.put(AES192_WRAP, "AES");
        BASE_CIPHER_NAMES.put(AES256_WRAP, "AES");

        WRAPPING_CIPHER_NAMES.put(AES128_WRAP, "AESWrap");
        WRAPPING_CIPHER_NAMES.put(AES192_WRAP, "AESWrap");
        WRAPPING_CIPHER_NAMES.put(AES256_WRAP, "AESWrap");

        ENCRYPTION_CIPHER_NAMES.put(DES_CBC, "DES/CBC/PKCS5Padding");
        ENCRYPTION_CIPHER_NAMES.put(RC2_CBC, "RC2/CBC/PKCS5Padding");
        ENCRYPTION_CIPHER_NAMES.put(DES_EDE3_CBC, "DESEDE/CBC/PKCS5Padding");
        ENCRYPTION_CIPHER_NAMES.put(AES128_CBC, "AES/CBC/PKCS5Padding");
        ENCRYPTION_CIPHER_NAMES.put(AES192_CBC, "AES/CBC/PKCS5Padding");
        ENCRYPTION_CIPHER_NAMES.put(AES256_CBC, "AES/CBC/PKCS5Padding");
    }

    private EnvelopedDataHelper() {
    }

    public static String getWrappingAlgorithmName(ASN1ObjectIdentifier algorithmOID) {
        if (!WRAPPING_CIPHER_NAMES.containsKey(algorithmOID))
            throw new IllegalArgumentException("Unsupported symmetric wrapper algorithm OID: " + algorithmOID);

        return WRAPPING_CIPHER_NAMES.get(algorithmOID);
    }

    public static String getEncryptionAlgorithmName(ASN1ObjectIdentifier algorithmOID) {
        if (!ENCRYPTION_CIPHER_NAMES.containsKey(algorithmOID))
            throw new IllegalArgumentException("Unsupported encryption algorithm OID: " + algorithmOID);

        return ENCRYPTION_CIPHER_NAMES.get(algorithmOID);
    }

    public static String getBaseCipherName(ASN1ObjectIdentifier algorithmOID) {
        if (!BASE_CIPHER_NAMES.containsKey(algorithmOID))
            throw new IllegalArgumentException("Unsupported base cipher algorithm OID: " + algorithmOID);

        return BASE_CIPHER_NAMES.get(algorithmOID);
    }

    public static SecretKey createKDF2KeyEncryptionKey(byte[] sharedSecret,
                                                       AlgorithmIdentifier keyEncryptionAlgorithm) {
        AlgorithmIdentifier keyEncryptionKeyAlgorithm =
                AlgorithmIdentifier.getInstance(keyEncryptionAlgorithm.getParameters());
        int secretKeyBitsLength = new DefaultSecretKeySizeProvider().getKeySize(keyEncryptionKeyAlgorithm);
        ECCCMSSharedInfo sharedInfo =
                new ECCCMSSharedInfo(keyEncryptionKeyAlgorithm, Pack.intToBigEndian(secretKeyBitsLength));

        KDF2BytesGenerator secretBytesGenerator =
                new KDF2BytesGenerator(createDigest(keyEncryptionAlgorithm.getAlgorithm()));
        try {
            secretBytesGenerator.init(new KDFParameters(sharedSecret, sharedInfo.getEncoded(ASN1Encoding.DER)));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to create KDF material.", e);
        }

        int secretKeyBytesLength = secretKeyBitsLength / 8;
        byte[] secretKeyBytes = new byte[secretKeyBytesLength];
        secretBytesGenerator.generateBytes(secretKeyBytes, 0, secretKeyBytesLength);

        return new SecretKeySpec(secretKeyBytes, getBaseCipherName(keyEncryptionKeyAlgorithm.getAlgorithm()));
    }

    public static Cipher createContentCipher(Key contentEncriptionKey, AlgorithmIdentifier contentEncryptionAlgorithm)
            throws CMSException {
        try {
            ASN1ObjectIdentifier encryptionAlgorithmOID = contentEncryptionAlgorithm.getAlgorithm();
            Cipher contentCipher = Cipher.getInstance(getEncryptionAlgorithmName(encryptionAlgorithmOID),
                    BouncyCastleProvider.PROVIDER_NAME);

            AlgorithmParameterSpec parameters;
            if (encryptionAlgorithmOID.equals(DES_CBC) || encryptionAlgorithmOID.equals(DES_EDE3_CBC) ||
                    encryptionAlgorithmOID.equals(AES128_CBC) || encryptionAlgorithmOID.equals(AES192_CBC) ||
                    encryptionAlgorithmOID.equals(AES256_CBC)) {
                ASN1OctetString iv = ASN1OctetString.getInstance(contentEncryptionAlgorithm.getParameters());
                parameters = new IvParameterSpec(iv.getOctets());
            } else if (encryptionAlgorithmOID == RC2_CBC) {
                ASN1Sequence encryptionParameters =
                        ASN1Sequence.getInstance(contentEncryptionAlgorithm.getParameters());
                ASN1OctetString iv = ASN1OctetString.getInstance(encryptionParameters.getObjectAt(1));
                parameters = new RC2ParameterSpec(contentEncriptionKey.getEncoded().length * 8, iv.getOctets());
            } else {
                throw new IllegalArgumentException("Unknown content encryption algorithm: " + encryptionAlgorithmOID);
            }

            contentCipher.init(Cipher.DECRYPT_MODE, contentEncriptionKey, parameters);

            return contentCipher;
        } catch (Exception e) {
            throw new CMSException("Failed to create the content cipher.", e);
        }
    }

    private static Digest createDigest(ASN1ObjectIdentifier keyAgreementAlgorithmOID) {
        if (keyAgreementAlgorithmOID.equals(ECDH_SHA1KDF)) {
            return DigestFactory.createSHA1();
        } else if (keyAgreementAlgorithmOID.equals(ECDH_SHA224KDF)) {
            return DigestFactory.createSHA224();
        } else if (keyAgreementAlgorithmOID.equals(ECDH_SHA256KDF)) {
            return DigestFactory.createSHA256();
        } else if (keyAgreementAlgorithmOID.equals(ECDH_SHA384KDF)) {
            return DigestFactory.createSHA384();
        } else if (keyAgreementAlgorithmOID.equals(ECDH_SHA512KDF)) {
            return DigestFactory.createSHA512();
        } else {
            throw new IllegalArgumentException("Unsupported KDF algorithm: " + keyAgreementAlgorithmOID);
        }
    }
}
