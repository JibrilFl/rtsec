/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import com.sun.jna.Memory;

import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.InputDecryptor;

import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.samples.pkcs11utils.Pkcs11Decryptor;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_GOST28147;

class RtInputDecryptor implements InputDecryptor {
    private final Pkcs11Decryptor mPkcs11Decryptor;
    private final long mKeyHandle;
    private final AlgorithmIdentifier mAlgorithmIdentifier;

    RtInputDecryptor(long sessionHandle, long keyHandle, AlgorithmIdentifier algorithmIdentifier) {
        mPkcs11Decryptor = new Pkcs11Decryptor(sessionHandle);
        mKeyHandle = keyHandle;
        mAlgorithmIdentifier = Objects.requireNonNull(algorithmIdentifier);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return mAlgorithmIdentifier;
    }

    @Override
    public InputStream getInputStream(InputStream inputStream) {
        try {
            byte[] data = new byte[inputStream.available()];
            inputStream.read(data);
            inputStream.close();
            GOST28147Parameters gost28147Parameters = GOST28147Parameters.getInstance(
                    mAlgorithmIdentifier.getParameters());

            byte[] iv = gost28147Parameters.getIV();
            Memory ivMemory = new Memory(iv.length);
            ivMemory.write(0, iv, 0, iv.length);

            byte[] decrypted = mPkcs11Decryptor.decrypt(data,
                    new CK_MECHANISM(CKM_GOST28147, ivMemory, ivMemory.size()), mKeyHandle);
            return new ByteArrayInputStream(decrypted);
        } catch (Pkcs11Exception | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
