/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputDecryptor;

import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.InputStream;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_RSA_PKCS;
import static ru.rutoken.samples.bouncycastle.utils.EnvelopedDataHelper.createContentCipher;
import static ru.rutoken.samples.bouncycastle.utils.EnvelopedDataHelper.getBaseCipherName;
import static ru.rutoken.samples.utils.CommonUtil.println;

public class RtRsaKeyTransEnvelopedRecipient implements KeyTransRecipient {
    private final long mSessionHandle;
    private final long mKeyHandle;

    public RtRsaKeyTransEnvelopedRecipient(long sessionHandle, long keyHandle) {
        mSessionHandle = sessionHandle;
        mKeyHandle = keyHandle;
    }

    @Override
    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg,
                                                  AlgorithmIdentifier contentEncryptionAlgorithm,
                                                  byte[] encryptedContentKey) throws CMSException {
        try {
            Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();

            NativeLong rv = pkcs11.C_DecryptInit(
                    new NativeLong(mSessionHandle),
                    new CK_MECHANISM(CKM_RSA_PKCS, null, 0),
                    new NativeLong(mKeyHandle)
            );
            Pkcs11Exception.throwIfNotOk("C_DecryptInit failed", rv);

            println("Get size of encrypted data");
            NativeLongByReference decryptedDataSize = new NativeLongByReference();
            rv = pkcs11.C_Decrypt(
                    new NativeLong(mSessionHandle),
                    encryptedContentKey,
                    new NativeLong(encryptedContentKey.length),
                    null,
                    decryptedDataSize
            );
            Pkcs11Exception.throwIfNotOk("C_Decrypt failed", rv);

            println("Decrypt data");
            byte[] decryptedData = new byte[decryptedDataSize.getValue().intValue()];
            rv = pkcs11.C_Decrypt(
                    new NativeLong(mSessionHandle),
                    encryptedContentKey,
                    new NativeLong(encryptedContentKey.length),
                    decryptedData,
                    decryptedDataSize
            );
            Pkcs11Exception.throwIfNotOk("C_Decrypt failed", rv);

            SecretKey keyEncryptionKey = new SecretKeySpec(decryptedData, 0, decryptedData.length,
                    getBaseCipherName(contentEncryptionAlgorithm.getAlgorithm()));
            final Cipher contentCipher = createContentCipher(keyEncryptionKey, contentEncryptionAlgorithm);

            return new RecipientOperator(new InputDecryptor() {
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return contentEncryptionAlgorithm;
                }

                public InputStream getInputStream(InputStream dataIn) {
                    return new CipherInputStream(dataIn, contentCipher);
                }
            });
        } catch (Exception e) {
            throw new CMSException("CMS decrypt error", e);
        }
    }
}
