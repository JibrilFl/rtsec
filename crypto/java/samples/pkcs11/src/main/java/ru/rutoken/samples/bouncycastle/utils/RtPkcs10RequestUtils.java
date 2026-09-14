/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.utils;

import com.sun.jna.NativeLong;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.bouncycastle.bcprimitives.RtStreamContentSigner;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;

import java.io.IOException;

import static ru.rutoken.samples.pkcs11utils.Pkcs11Operations.getEcdsaPublicKeyEcPoint;
import static ru.rutoken.samples.pkcs11utils.Pkcs11Operations.getEcdsaPublicKeyParameters;

public final class RtPkcs10RequestUtils {
    private RtPkcs10RequestUtils() {
    }

    /**
     * Creates a PKCS#10 certification request (CSR) with the passed ECDSA key pair.
     * </br>
     *
     * @param session       current PKCS#11 session
     * @param publicKey     ECDSA public key
     * @param privateKey    ECDSA private key
     * @param signAlgorithm ECDSA signature algorithm used to sign CSR (see {@link SignAlgorithm} class)
     * @param dn            list of DNs (Distinguished Names) fields
     * @param extensions    list of certificate extensions fields
     * @return encoded CSR.
     */
    public static byte[] createCsrOnEcdsaKeys(Pkcs11 pkcs11, NativeLong session, NativeLong publicKey,
                                              NativeLong privateKey, SignAlgorithm signAlgorithm, RDN[] dn,
                                              Extensions extensions) throws IOException, Pkcs11Exception {
        byte[] ecPoint = getEcdsaPublicKeyEcPoint(pkcs11, session, publicKey);
        ASN1Encodable ecParameters = getEcdsaPublicKeyParameters(pkcs11, session, publicKey);
        AlgorithmIdentifier publicKeyAlgorithm =
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecParameters);
        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(publicKeyAlgorithm, ecPoint);

        ContentSigner signer = new RtStreamContentSigner(signAlgorithm, session.longValue(), privateKey.longValue());

        PKCS10CertificationRequestBuilder csrBuilder =
                new PKCS10CertificationRequestBuilder(new X500Name(dn), publicKeyInfo);
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        return csr.getEncoded();
    }
}
