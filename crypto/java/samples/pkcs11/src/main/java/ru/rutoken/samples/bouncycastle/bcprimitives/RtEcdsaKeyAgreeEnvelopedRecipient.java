/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyAgreeRecipient;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.InputDecryptor;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import java.io.InputStream;
import java.security.Key;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_EXTRACTABLE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_KEY_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_LABEL;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_PRIVATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_SENSITIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_TOKEN;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_GENERIC_SECRET;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_SECRET_KEY;
import static ru.rutoken.samples.bouncycastle.utils.EnvelopedDataHelper.createContentCipher;
import static ru.rutoken.samples.bouncycastle.utils.EnvelopedDataHelper.createKDF2KeyEncryptionKey;
import static ru.rutoken.samples.bouncycastle.utils.EnvelopedDataHelper.getBaseCipherName;
import static ru.rutoken.samples.bouncycastle.utils.EnvelopedDataHelper.getWrappingAlgorithmName;
import static ru.rutoken.samples.pkcs11utils.Pkcs11Operations.deriveEcdhKey;

public class RtEcdsaKeyAgreeEnvelopedRecipient implements KeyAgreeRecipient {
    private static final CK_ATTRIBUTE[] derivedKeyTemplate;

    static {
        derivedKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(7);
        derivedKeyTemplate[0].setAttr(CKA_LABEL, "Derived Secret key");
        derivedKeyTemplate[1].setAttr(CKA_CLASS, CKO_SECRET_KEY);
        derivedKeyTemplate[2].setAttr(CKA_KEY_TYPE, CKK_GENERIC_SECRET);
        derivedKeyTemplate[3].setAttr(CKA_TOKEN, false);
        derivedKeyTemplate[4].setAttr(CKA_PRIVATE, true); // Accessible only after authentication
        derivedKeyTemplate[5].setAttr(CKA_EXTRACTABLE, true); // Key may be extracted in encrypted form
        derivedKeyTemplate[6].setAttr(CKA_SENSITIVE, false); // Key may be extracted in open form
    }

    private final long mSessionHandle;
    private final long mPrivateKeyHandle;

    public RtEcdsaKeyAgreeEnvelopedRecipient(long sessionHandle, long keyHandle) {
        mSessionHandle = sessionHandle;
        mPrivateKeyHandle = keyHandle;
    }

    @Override
    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
                                                  AlgorithmIdentifier contentEncryptionAlgorithm,
                                                  SubjectPublicKeyInfo senderPublicKey,
                                                  ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey)
            throws CMSException {
        try {
            Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();

            byte[] ecdsaPublicKeyOctets =
                    new DEROctetString(senderPublicKey.getPublicKeyData().getOctets()).getEncoded();
            byte[] ecdhBytes =
                    deriveEcdhKey(pkcs11, mSessionHandle, ecdsaPublicKeyOctets, mPrivateKeyHandle, derivedKeyTemplate);

            SecretKey keyEncryptionKey = createKDF2KeyEncryptionKey(ecdhBytes, keyEncryptionAlgorithm);

            AlgorithmIdentifier keyEncryptionKeyAlgorithm =
                    AlgorithmIdentifier.getInstance(keyEncryptionAlgorithm.getParameters());
            Key contentEncriptonKey = unwrapContentEncriptonKey(keyEncryptionKeyAlgorithm, keyEncryptionKey,
                    contentEncryptionAlgorithm, encryptedContentKey);

            final Cipher contentCipher = createContentCipher(contentEncriptonKey, contentEncryptionAlgorithm);

            return new RecipientOperator(new InputDecryptor() {
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return contentEncryptionAlgorithm;
                }

                public InputStream getInputStream(InputStream dataIn) {
                    return new CipherInputStream(dataIn, contentCipher);
                }
            });
        } catch (Exception e) {
            throw new CMSException("Failed to create the RecipientOperator.", e);
        }
    }

    @Override
    public AlgorithmIdentifier getPrivateKeyAlgorithmIdentifier() {
        return new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey);
    }

    private Key unwrapContentEncriptonKey(AlgorithmIdentifier keyEncryptionKeyAlgorithm, SecretKey keyEncryptionKey,
                                          AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
            throws CMSException {
        try {
            Cipher keyUnwrapCipher =
                    Cipher.getInstance(getWrappingAlgorithmName(keyEncryptionKeyAlgorithm.getAlgorithm()),
                            BouncyCastleProvider.PROVIDER_NAME);
            keyUnwrapCipher.init(Cipher.UNWRAP_MODE, keyEncryptionKey);

            return keyUnwrapCipher.unwrap(encryptedContentKey,
                    getBaseCipherName(contentEncryptionAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
        } catch (Exception e) {
            throw new CMSException("Failed to unwrap the content encryption key.", e);
        }
    }
}
