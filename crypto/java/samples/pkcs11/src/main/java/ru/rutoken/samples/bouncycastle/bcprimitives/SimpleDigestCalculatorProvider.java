/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;

import java.util.Objects;

public class SimpleDigestCalculatorProvider implements DigestCalculatorProvider {
    private final DigestCalculator mDigestCalculator;

    public SimpleDigestCalculatorProvider(DigestCalculator digestCalculator) {
        mDigestCalculator = Objects.requireNonNull(digestCalculator);
    }

    @Override
    public DigestCalculator get(AlgorithmIdentifier algorithmIdentifier) {
        return mDigestCalculator;
    }
}
