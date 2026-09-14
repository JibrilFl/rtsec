/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
import org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.util.Arrays;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.pkcs11utils.CK_GOSTR3410_DERIVE_PARAMS_JRT;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;
import ru.rutoken.samples.utils.Util;

import java.io.IOException;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.pkcs11jna.Pkcs11Tc26Constants.CKM_GOSTR3410_12_DERIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Tc26Constants.CKM_KDF_4357;

public class RtGostKeyTransEnvelopedRecipient implements KeyTransRecipient {
    private static final long CKD_CPDIVERSIFY_KDF_JRT = 0x90000009;
    private final long mSessionHandle;
    private final long mKeyHandle;

    public RtGostKeyTransEnvelopedRecipient(long sessionHandle, long keyHandle) {
        mSessionHandle = sessionHandle;
        mKeyHandle = keyHandle;
    }

    @Override
    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg,
                                                  AlgorithmIdentifier contentEncryptionAlgorithm,
                                                  byte[] encryptedContentKey) throws CMSException {
        try {
            Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();

            GostR3410KeyTransport transport = GostR3410KeyTransport.getInstance(encryptedContentKey);
            GostR3410TransportParameters transportParameters = transport.getTransportParameters();

            // Derive to get KEK (Key Encryption Key)
            CK_ATTRIBUTE[] deriveTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(4);
            deriveTemplate[0].setAttr(CKA_CLASS, CKO_SECRET_KEY);
            deriveTemplate[1].setAttr(CKA_KEY_TYPE, CKK_GOST28147);
            deriveTemplate[2].setAttr(CKA_TOKEN, false);
            deriveTemplate[3].setAttr(CKA_GOST28147_PARAMS, transportParameters.getEncryptionParamSet().getEncoded());

            NativeLongByReference derivedKeyPointer = new NativeLongByReference();
            NativeLong rv = pkcs11.C_DeriveKey(new NativeLong(mSessionHandle), makeDeriveMechanism(transportParameters),
                    new NativeLong(mKeyHandle), deriveTemplate, new NativeLong(deriveTemplate.length),
                    derivedKeyPointer);
            Pkcs11Exception.throwIfNotOk("C_DeriveKey failed", rv);
            NativeLong derivedKey = derivedKeyPointer.getValue();

            // Unwrap CEK (Content Encryption Key)
            Memory ukmMemory = new Memory(transportParameters.getUkm().length);
            ukmMemory.write(0, transportParameters.getUkm(), 0, transportParameters.getUkm().length);
            CK_MECHANISM unwrapMechanism = new CK_MECHANISM(CKM_GOST28147_KEY_WRAP, ukmMemory, ukmMemory.size());

            byte[] wrappedKey = Arrays.concatenate(transport.getSessionEncryptedKey().getEncryptedKey(),
                    transport.getSessionEncryptedKey().getMacKey());

            GOST28147Parameters gost28147Parameters = GOST28147Parameters.getInstance(contentEncryptionAlgorithm
                    .getParameters());
            CK_ATTRIBUTE[] sessionKeyAttributes = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(6);
            sessionKeyAttributes[0].setAttr(CKA_CLASS, CKO_SECRET_KEY);
            sessionKeyAttributes[1].setAttr(CKA_KEY_TYPE, CKK_GOST28147);
            sessionKeyAttributes[2].setAttr(CKA_TOKEN, false);
            sessionKeyAttributes[3].setAttr(CKA_SENSITIVE, false);
            sessionKeyAttributes[4].setAttr(CKA_EXTRACTABLE, true);
            sessionKeyAttributes[5].setAttr(CKA_GOST28147_PARAMS,
                    gost28147Parameters.getEncryptionParamSet().getEncoded());

            NativeLongByReference unwrapedKeyPointer = new NativeLongByReference();
            rv = pkcs11.C_UnwrapKey(new NativeLong(mSessionHandle), unwrapMechanism, derivedKey,
                    wrappedKey, new NativeLong(wrappedKey.length),
                    sessionKeyAttributes, new NativeLong(sessionKeyAttributes.length), unwrapedKeyPointer);
            Pkcs11Exception.throwIfNotOk("C_UnwrapKey failed", rv);

            return new RecipientOperator(new RtInputDecryptor(mSessionHandle, unwrapedKeyPointer.getValue().longValue(),
                    contentEncryptionAlgorithm));
        } catch (Pkcs11Exception | IOException e) {
            throw new CMSException("CMS decrypt error", e);
        }
    }

    private CK_MECHANISM makeDeriveMechanism(GostR3410TransportParameters transportParameters) throws IOException {
        byte[] publicKey = ASN1OctetString.getInstance(transportParameters.getEphemeralPublicKey().parsePublicKey())
                .getOctets();
        byte[] ukm = transportParameters.getUkm();
        if (CryptoProObjectIdentifiers.gostR3410_2001.equals(transportParameters.getEphemeralPublicKey()
                .getAlgorithm().getAlgorithm())) {
            CK_GOSTR3410_DERIVE_PARAMS_JRT deriveParameters = new CK_GOSTR3410_DERIVE_PARAMS_JRT(
                    new NativeLong(CKD_CPDIVERSIFY_KDF_JRT), new NativeLong(publicKey.length), publicKey,
                    new NativeLong(ukm.length), ukm);
            deriveParameters.write();
            return new CK_MECHANISM(CKM_GOSTR3410_DERIVE, deriveParameters.getPointer(), deriveParameters.size());
        } else { // 2012
            Memory deriveParameters = Util.allocateDeriveParamsGOSTR3410_2012((int) CKM_KDF_4357, publicKey, ukm);
            return new CK_MECHANISM(CKM_GOSTR3410_12_DERIVE, deriveParameters, deriveParameters.size());
        }
    }
}
