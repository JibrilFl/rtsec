/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;

import ru.rutoken.samples.pkcs11utils.Pkcs11Signer;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;

import java.io.IOException;
import java.io.OutputStream;

public class RtStreamContentSigner implements ContentSigner {
    private final Pkcs11Signer mPkcs11Signer;
    private final DigestCalculator mDigestCalculator;

    public RtStreamContentSigner(SignAlgorithm signAlgorithm, long sessionHandle, long privateKeyHandle) {
        mPkcs11Signer = new Pkcs11Signer(signAlgorithm, sessionHandle, privateKeyHandle);
        mDigestCalculator = new StreamDigestCalculator(signAlgorithm.getDigestAlgorithm().makeDigest(sessionHandle));
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return mPkcs11Signer.getSignAlgorithm().getAlgorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
        return mDigestCalculator.getOutputStream();
    }

    @Override
    public byte[] getSignature() {
        try {
            final byte[] digest =
                    mPkcs11Signer.getSignAlgorithm().isRsa() ? createRsaDigestInfo(mDigestCalculator.getDigest()) :
                            mDigestCalculator.getDigest();
            return mPkcs11Signer.sign(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] createRsaDigestInfo(byte[] digest) throws IOException {
        DigestInfo digestInfo = new DigestInfo(mPkcs11Signer.getDigestAlgorithm().getAlgorithmIdentifier(), digest);
        return digestInfo.getEncoded();
    }
}
