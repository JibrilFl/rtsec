/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_ECDSA;

public class Pkcs11Signer {
    private final SignAlgorithm mSignAlgorithm;
    private final long mSessionHandle;
    private final long mPrivateKeyHandle;

    public Pkcs11Signer(SignAlgorithm signAlgorithm, long sessionHandle, long privateKeyHandle) {
        mSignAlgorithm = signAlgorithm;
        mSessionHandle = sessionHandle;
        mPrivateKeyHandle = privateKeyHandle;
    }

    public SignAlgorithm getSignAlgorithm() {
        return mSignAlgorithm;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return mSignAlgorithm.getDigestAlgorithm();
    }

    public byte[] sign(byte[] data) throws Pkcs11Exception, IOException {
        final Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        final CK_MECHANISM mechanism = new CK_MECHANISM(mSignAlgorithm.getPkcsMechanism(), Pointer.NULL, 0);
        NativeLong rv = pkcs11.C_SignInit(new NativeLong(mSessionHandle), mechanism, new NativeLong(mPrivateKeyHandle));
        Pkcs11Exception.throwIfNotOk("C_SignInit failed", rv);

        final NativeLongByReference count = new NativeLongByReference();
        rv = pkcs11.C_Sign(new NativeLong(mSessionHandle), data, new NativeLong(data.length), null, count);
        Pkcs11Exception.throwIfNotOk("C_Sign failed", rv);

        final byte[] signature = new byte[count.getValue().intValue()];
        rv = pkcs11.C_Sign(new NativeLong(mSessionHandle), data, new NativeLong(data.length), signature, count);
        Pkcs11Exception.throwIfNotOk("C_Sign failed", rv);

        if (mSignAlgorithm.getPkcsMechanism() == CKM_ECDSA) {
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, signature.length / 2));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, signature.length / 2, signature.length));
            ASN1EncodableVector encodableVector = new ASN1EncodableVector();
            encodableVector.add(new ASN1Integer(r));
            encodableVector.add(new ASN1Integer(s));

            return new DERSequence(encodableVector).getEncoded(ASN1Encoding.DER);
        }

        return signature;
    }
}
