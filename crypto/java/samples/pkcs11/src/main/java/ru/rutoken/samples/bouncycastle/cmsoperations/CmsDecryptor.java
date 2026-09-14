/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.cmsoperations;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyAgreeRecipient;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;

import ru.rutoken.samples.bouncycastle.bcprimitives.RtEcdsaKeyAgreeEnvelopedRecipient;
import ru.rutoken.samples.bouncycastle.bcprimitives.RtGostKeyTransEnvelopedRecipient;
import ru.rutoken.samples.bouncycastle.bcprimitives.RtRsaKeyTransEnvelopedRecipient;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import static org.bouncycastle.cms.CMSAlgorithm.GOST28147_GCFB;

class CmsDecryptor {
    private final long mSessionHandle;

    CmsDecryptor(long sessionHandle) {
        mSessionHandle = sessionHandle;
    }

    byte[] decrypt(byte[] data, long keyHandle, List<X509Certificate> possibleRecipients) throws CMSException {
        final CMSEnvelopedData cms = new CMSEnvelopedData(data);
        RecipientInformationStore recipientsStore = cms.getRecipientInfos();

        for (X509Certificate certificate : possibleRecipients) {
            Collection<RecipientInformation> keyTransRecipients = matchKeyTransRecipients(recipientsStore, certificate);
            if (!keyTransRecipients.isEmpty()) {
                return keyTransRecipients.iterator()
                        .next()
                        .getContent(makeKeyTransEnvelopedRecipient(cms.getContentEncryptionAlgorithm(), keyHandle));
            }

            Collection<RecipientInformation> keyAgreeRecipients = matchKeyAgreeRecipients(recipientsStore, certificate);
            if (!keyAgreeRecipients.isEmpty()) {
                return keyAgreeRecipients.iterator()
                        .next()
                        .getContent(makeKeyAgreeEnvelopedRecipient(keyHandle));
            }
        }

        throw new IllegalStateException("Corresponding RecipientInformation is absent.");
    }

    private Collection<RecipientInformation> matchKeyTransRecipients(RecipientInformationStore recipientsStore,
                                                                     X509Certificate possibleRecipientCert) {
        return recipientsStore.getRecipients(new JceKeyTransRecipientId(possibleRecipientCert));
    }

    private Collection<RecipientInformation> matchKeyAgreeRecipients(RecipientInformationStore recipientsStore,
                                                                     X509Certificate possibleRecipientCert) {
        return recipientsStore.getRecipients(new JceKeyAgreeRecipientId(possibleRecipientCert));
    }

    private KeyTransRecipient makeKeyTransEnvelopedRecipient(AlgorithmIdentifier contentEncryptionAlgorithm,
                                                             long keyHandle) {
        if (contentEncryptionAlgorithm.getAlgorithm() == GOST28147_GCFB) {
            return new RtGostKeyTransEnvelopedRecipient(mSessionHandle, keyHandle);
        } else {
            return new RtRsaKeyTransEnvelopedRecipient(mSessionHandle, keyHandle);
        }
    }

    private KeyAgreeRecipient makeKeyAgreeEnvelopedRecipient(long keyHandle) {
        return new RtEcdsaKeyAgreeEnvelopedRecipient(mSessionHandle, keyHandle);
    }
}
