/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;

import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.samples.pkcs11utils.DigestAlgorithm;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import java.util.Arrays;
import java.util.Objects;

public class RtDigest implements Digest {
    private final DigestAlgorithm mDigestAlgorithm;
    private final long mSessionHandle;
    private final Pkcs11 mPkcs11 = RtPkcs11Library.getPkcs11Interface();
    private boolean mIsOperationInitialized = false;

    public RtDigest(DigestAlgorithm digestAlgorithm, long sessionHandle) {
        mDigestAlgorithm = Objects.requireNonNull(digestAlgorithm);
        mSessionHandle = sessionHandle;
    }

    private static void checkReturnValue(NativeLong rv, String functionName) {
        if (rv.longValue() != Pkcs11Constants.CKR_OK)
            throw new RuntimeCryptoException(functionName + " failed with rv: " + rv.intValue());
    }

    @Override
    public String getAlgorithmName() {
        return mDigestAlgorithm.getAlgorithmName();
    }

    @Override
    public int getDigestSize() {
        return mDigestAlgorithm.getDigestSize();
    }

    @Override
    public void update(byte in) {
        update(new byte[]{in});
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        final byte[] chunk = Arrays.copyOfRange(in, inOff, inOff + len);
        update(chunk);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        final NativeLongByReference count = new NativeLongByReference();
        NativeLong rv = mPkcs11.C_DigestFinal(new NativeLong(mSessionHandle), null, count);
        checkReturnValue(rv, "C_DigestFinal");

        final byte[] digest = new byte[count.getValue().intValue()];
        rv = mPkcs11.C_DigestFinal(new NativeLong(mSessionHandle), digest, count);
        checkReturnValue(rv, "C_DigestFinal");

        mIsOperationInitialized = false;

        final int length = count.getValue().intValue();
        System.arraycopy(digest, 0, out, outOff, length);
        return length;
    }

    @Override
    public void reset() {
        if (mIsOperationInitialized) {
            final byte[] result = new byte[getDigestSize()];
            doFinal(result, 0);
        }
    }

    private void update(byte[] chunk) {
        NativeLong rv;
        if (!mIsOperationInitialized) {
            final Pointer parameter = new Memory(mDigestAlgorithm.getAlgorithmParamset().length);
            parameter.write(0, mDigestAlgorithm.getAlgorithmParamset(), 0,
                    mDigestAlgorithm.getAlgorithmParamset().length);
            // Pass null as parameter and 0 as parameter length if you want to perform hardware digest
            final CK_MECHANISM mechanism = new CK_MECHANISM(mDigestAlgorithm.getPkcsMechanism(), parameter,
                    mDigestAlgorithm.getAlgorithmParamset().length);

            rv = mPkcs11.C_DigestInit(new NativeLong(mSessionHandle), mechanism);
            checkReturnValue(rv, "C_DigestInit");
            mIsOperationInitialized = true;
        }

        rv = mPkcs11.C_DigestUpdate(new NativeLong(mSessionHandle), chunk, new NativeLong(chunk.length));
        checkReturnValue(rv, "C_DigestUpdate");
    }
}
