/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.cmsoperations;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;

import ru.rutoken.samples.bouncycastle.bcprimitives.RtStreamContentSigner;
import ru.rutoken.samples.bouncycastle.bcprimitives.SimpleDigestCalculatorProvider;
import ru.rutoken.samples.bouncycastle.bcprimitives.StreamDigestCalculator;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public class StreamCmsSigner {
    private final RtStreamContentSigner mStreamContentSigner;
    private final DigestCalculator mDigestCalculator;
    private final ByteArrayOutputStream mStream = new ByteArrayOutputStream();

    public StreamCmsSigner(SignAlgorithm signAlgorithm, long sessionHandle, long privateKeyHandle) {
        mDigestCalculator = new StreamDigestCalculator(signAlgorithm.getDigestAlgorithm().makeDigest(sessionHandle));
        mStreamContentSigner = new RtStreamContentSigner(signAlgorithm, sessionHandle, privateKeyHandle);
    }

    public OutputStream openDataStream(X509CertificateHolder signerCertificate, boolean isAttached) {
        return openDataStream(signerCertificate, isAttached, null);
    }

    public OutputStream openDataStream(X509CertificateHolder signerCertificate, boolean isAttached,
                                       CMSAttributeTableGenerator signedAttributeGenerator) {
        final CMSSignedDataStreamGenerator generator = new CMSSignedDataStreamGenerator();
        try {
            generator.addCertificate(signerCertificate);

            SignerInfoGeneratorBuilder builder =
                    new SignerInfoGeneratorBuilder(new SimpleDigestCalculatorProvider(mDigestCalculator));

            if (signedAttributeGenerator != null)
                builder.setSignedAttributeGenerator(signedAttributeGenerator);

            generator.addSignerInfoGenerator(builder.build(mStreamContentSigner, signerCertificate));

            return generator.open(mStream, isAttached);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getSignature() {
        return mStream.toByteArray();
    }
}
