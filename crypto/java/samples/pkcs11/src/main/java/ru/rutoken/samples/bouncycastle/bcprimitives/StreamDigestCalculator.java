/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;

import java.io.OutputStream;
import java.util.Objects;

public class StreamDigestCalculator implements DigestCalculator {
    private final Digest mDigest;
    private final DigestOutputStream mStream;

    public StreamDigestCalculator(Digest digest) {
        mDigest = Objects.requireNonNull(digest);
        mStream = new DigestOutputStream(mDigest);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new DefaultDigestAlgorithmIdentifierFinder().find(mDigest.getAlgorithmName());
    }

    @Override
    public byte[] getDigest() {
        return mStream.getDigest();
    }

    @Override
    public OutputStream getOutputStream() {
        return mStream;
    }
}
