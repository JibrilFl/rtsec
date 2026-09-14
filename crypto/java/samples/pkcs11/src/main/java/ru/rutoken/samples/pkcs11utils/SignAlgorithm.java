/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_ECDSA;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_GOSTR3410;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_RSA_PKCS;
import static ru.rutoken.pkcs11jna.Pkcs11Tc26Constants.CKM_GOSTR3410_512;

/**
 * We must use these signature algorithm identifiers according to the following RFCs:
 * <ul>
 *   <li>for GOST signature algorithms: RFC 4491, sec 2.2.2 and RFC 9215, sec 2;</li>
 *   <li>for RSA signature algorithms: RFC 3370, sec 3.2 and RFC 5754, sec 3.2;</li>
 *   <li>for ECDSA signature algorithms: RFC 3279, sec 2.2.3 and RFC 5758, sec 3.2.</li>
 * </ul>
 */
public enum SignAlgorithm {
    GOSTR3410_2001(
            CKM_GOSTR3410,
            new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001),
            DigestAlgorithm.GOSTR3411_1994,
            false
    ),
    GOSTR3410_2012_256(
            CKM_GOSTR3410,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256),
            DigestAlgorithm.GOSTR3411_2012_256,
            false
    ),
    GOSTR3410_2012_512(
            CKM_GOSTR3410_512,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512),
            DigestAlgorithm.GOSTR3411_2012_512,
            false
    ),
    RSA_SHA1(
            CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption),
            DigestAlgorithm.SHA1,
            true
    ),
    RSA_SHA224(
            CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha224WithRSAEncryption),
            DigestAlgorithm.SHA224,
            true
    ),
    RSA_SHA256(
            CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption),
            DigestAlgorithm.SHA256,
            true
    ),
    RSA_SHA384(
            CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha384WithRSAEncryption),
            DigestAlgorithm.SHA384,
            true
    ),
    RSA_SHA512(
            CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha512WithRSAEncryption),
            DigestAlgorithm.SHA512,
            true
    ),
    RSA_MD5(
            CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption),
            DigestAlgorithm.MD5,
            true
    ),
    ECDSA_SHA1(
            CKM_ECDSA,
            new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1),
            DigestAlgorithm.SHA1,
            false
    ),
    ECDSA_SHA224(
            CKM_ECDSA,
            new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA224),
            DigestAlgorithm.SHA224,
            false
    ),
    ECDSA_SHA256(
            CKM_ECDSA,
            new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256),
            DigestAlgorithm.SHA256,
            false
    ),
    ECDSA_SHA384(
            CKM_ECDSA,
            new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA384),
            DigestAlgorithm.SHA384,
            false
    ),
    ECDSA_SHA512(
            CKM_ECDSA,
            new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA512),
            DigestAlgorithm.SHA512,
            false
    );

    private final long mPkcsMechanism;
    private final AlgorithmIdentifier mAlgorithmIdentifier;
    private final DigestAlgorithm mDigestAlgorithm;
    private final boolean mIsRsa;

    SignAlgorithm(long pkcsMechanism, AlgorithmIdentifier algorithmIdentifier, DigestAlgorithm digestAlgorithm,
                  boolean isRsa) {
        mPkcsMechanism = pkcsMechanism;
        mAlgorithmIdentifier = algorithmIdentifier;
        mDigestAlgorithm = digestAlgorithm;
        mIsRsa = isRsa;
    }

    public long getPkcsMechanism() {
        return mPkcsMechanism;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return mAlgorithmIdentifier;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return mDigestAlgorithm;
    }

    public boolean isRsa() {
        return mIsRsa;
    }
}
