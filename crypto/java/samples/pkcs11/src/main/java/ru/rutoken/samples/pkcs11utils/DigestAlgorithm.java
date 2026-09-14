/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

import ru.rutoken.samples.bouncycastle.bcprimitives.RtDigest;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.pkcs11jna.Pkcs11Tc26Constants.CKM_GOSTR3411_12_256;
import static ru.rutoken.pkcs11jna.Pkcs11Tc26Constants.CKM_GOSTR3411_12_512;

public enum DigestAlgorithm {
    GOSTR3411_1994(CKM_GOSTR3411, "GOST3411", Constants.ATTR_GOSTR3411_1994, 32) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new RtDigest(this, sessionHandle);
        }
    },
    GOSTR3411_2012_256(CKM_GOSTR3411_12_256, "GOST3411-2012-256", Constants.ATTR_GOSTR3411_2012_256, 32) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new RtDigest(this, sessionHandle);
        }
    },
    GOSTR3411_2012_512(CKM_GOSTR3411_12_512, "GOST3411-2012-512", Constants.ATTR_GOSTR3411_2012_512, 64) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new RtDigest(this, sessionHandle);
        }
    },
    SHA1(CKM_SHA_1, "SHA-1", null, 20) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new SHA1Digest();
        }
    },
    SHA224(CKM_SHA224, "SHA-224", null, 28) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new SHA224Digest();
        }
    },
    SHA256(CKM_SHA256, "SHA-256", null, 32) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new SHA256Digest();
        }
    },
    SHA384(CKM_SHA384, "SHA-384", null, 48) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new SHA384Digest();
        }
    },
    SHA512(CKM_SHA512, "SHA-512", null, 64) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new SHA512Digest();
        }
    },
    MD5(CKM_MD5, "MD5", null, 16) {
        @Override
        public Digest makeDigest(long sessionHandle) {
            return new MD5Digest();
        }
    };

    private final long mPkcsMechanism;
    private final AlgorithmIdentifier mAlgorithmIdentifier;
    private final byte[] mParamset;
    private final String mAlgorithmName;
    private final int mDigestSize; // in bytes

    DigestAlgorithm(long pkcsMechanism, String algorithmName, byte[] paramset, int digestSize) {
        mPkcsMechanism = pkcsMechanism;
        mAlgorithmIdentifier = new DefaultDigestAlgorithmIdentifierFinder().find(algorithmName);
        mParamset = paramset;
        mAlgorithmName = algorithmName;
        mDigestSize = digestSize;
    }

    public long getPkcsMechanism() {
        return mPkcsMechanism;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return mAlgorithmIdentifier;
    }

    public byte[] getAlgorithmParamset() {
        return mParamset;
    }

    public String getAlgorithmName() {
        return mAlgorithmName;
    }

    public int getDigestSize() {
        return mDigestSize;
    }

    public abstract Digest makeDigest(long sessionHandle);
}
