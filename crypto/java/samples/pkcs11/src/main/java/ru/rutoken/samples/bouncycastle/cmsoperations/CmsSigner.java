/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.cmsoperations;

import org.bouncycastle.cert.X509CertificateHolder;

import ru.rutoken.samples.pkcs11utils.SignAlgorithm;

import java.io.IOException;
import java.io.OutputStream;

class CmsSigner {
    private final StreamCmsSigner mStreamCmsSigner;

    CmsSigner(SignAlgorithm signAlgorithm, long sessionHandle, long privateKeyHandle) {
        mStreamCmsSigner = new StreamCmsSigner(signAlgorithm, sessionHandle, privateKeyHandle);
    }

    byte[] signAttached(byte[] data, X509CertificateHolder signerCertificate) throws IOException {
        return sign(data, signerCertificate, true);
    }

    byte[] signDetached(byte[] data, X509CertificateHolder signerCertificate) throws IOException {
        return sign(data, signerCertificate, false);
    }

    private byte[] sign(byte[] data, X509CertificateHolder signerCertificate, boolean attached) throws IOException {
        try (OutputStream stream = mStreamCmsSigner.openDataStream(signerCertificate, attached)) {
            stream.write(data);
        }

        return mStreamCmsSigner.getSignature();
    }
}
