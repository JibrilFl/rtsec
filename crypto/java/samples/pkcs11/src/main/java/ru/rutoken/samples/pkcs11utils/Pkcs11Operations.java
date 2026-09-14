/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_ECDH1_DERIVE_PARAMS;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.CK_MECHANISM_INFO;
import ru.rutoken.pkcs11jna.Pkcs11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_EC_PARAMS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_EC_POINT;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_KEY_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_MODULUS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_PUBLIC_EXPONENT;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_TOKEN;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_VALUE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKD_NULL;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_EC;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_RSA;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_ECDH1_DERIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PRIVATE_KEY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PUBLIC_KEY;
import static ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations.findFirstObject;
import static ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations.findObjects;
import static ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations.getAttributeValues;
import static ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations.getCertificateValue;
import static ru.rutoken.samples.utils.CommonUtil.printHex;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.Util.getCertificateInfo;

/**
 * Common operations on pkcs11
 */
public final class Pkcs11Operations {
    private Pkcs11Operations() {
    }

    public static CK_MECHANISM_INFO getMechanismInfo(Pkcs11 pkcs11, NativeLong slot, long mechanism)
            throws Pkcs11Exception {
        final CK_MECHANISM_INFO ckInfo = new CK_MECHANISM_INFO();
        NativeLong rv = pkcs11.C_GetMechanismInfo(slot, new NativeLong(mechanism), ckInfo);
        Pkcs11Exception.throwIfNotOk("C_GetMechanismInfo failed", rv);

        return ckInfo;
    }

    public static byte[] getEcdsaPublicKeyEcPoint(Pkcs11 pkcs11, NativeLong session, NativeLong publicKey)
            throws Pkcs11Exception {
        CK_ATTRIBUTE[] publicKeyTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        publicKeyTemplate[0].setAttr(CKA_EC_POINT, null, 0);
        getAttributeValues(pkcs11, session, publicKey, publicKeyTemplate);
        byte[] octetStringEcPoint = publicKeyTemplate[0].pValue.getByteArray(0,
                publicKeyTemplate[0].ulValueLen.intValue());

        return ASN1OctetString.getInstance(octetStringEcPoint).getOctets();
    }

    public static ASN1Encodable getEcdsaPublicKeyParameters(Pkcs11 pkcs11, NativeLong session, NativeLong publicKey)
            throws Pkcs11Exception {
        CK_ATTRIBUTE[] publicKeyTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        publicKeyTemplate[0].setAttr(CKA_EC_PARAMS, null, 0);
        getAttributeValues(pkcs11, session, publicKey, publicKeyTemplate);
        byte[] octetStringParameters = publicKeyTemplate[0].pValue.getByteArray(0,
                publicKeyTemplate[0].ulValueLen.intValue());

        return X962Parameters.getInstance(octetStringParameters);
    }

    public static byte[] getKeyValue(Pkcs11 pkcs11, NativeLong session, NativeLong key) throws Pkcs11Exception {
        CK_ATTRIBUTE[] keyValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        keyValueTemplate[0].setAttr(CKA_VALUE, null, 0);
        getAttributeValues(pkcs11, session, key, keyValueTemplate);

        return keyValueTemplate[0].pValue.getByteArray(0, keyValueTemplate[0].ulValueLen.intValue());
    }

    public static void printAllCertificatesInfo(Pkcs11 pkcs11, NativeLong session) throws Pkcs11Exception, IOException {
        CK_ATTRIBUTE[] certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_TOKEN, true);

        NativeLong[] certificates = findObjects(pkcs11, session, certificateTemplate, 100);
        for (NativeLong certificate : certificates) {
            println(getCertificateInfo(getCertificateValue(pkcs11, session, certificate)));
        }
    }

    public static byte[] getFirstCertificateValue(Pkcs11 pkcs11, NativeLong session, CK_ATTRIBUTE[] certificateTemplate)
            throws Pkcs11Exception {
        return getCertificateValue(pkcs11, session, findFirstObject(pkcs11, session, certificateTemplate));
    }

    public static NativeLong findPrivateKeyByCertificateValue(Pkcs11 pkcs11, NativeLong session,
                                                              byte[] certificateValue)
            throws Pkcs11Exception, CertificateException, IOException {
        return findKeyPairByCertificateValue(pkcs11, session, certificateValue).privateKey;
    }

    public static KeyPair findKeyPairByCertificateValue(Pkcs11 pkcs11, NativeLong session, byte[] certificateValue)
            throws Pkcs11Exception, CertificateException, IOException {
        // Find corresponding public key handle for certificate
        println("Parsing X.509 certificate");
        X509Certificate x509certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificateValue));

        final CK_ATTRIBUTE[] publicKeyValueTemplate;
        if (x509certificate.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey publicKey = (RSAPublicKey) x509certificate.getPublicKey();

            println("Finding public key by modulus and exponent");
            publicKeyValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(4);
            publicKeyValueTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
            publicKeyValueTemplate[1].setAttr(CKA_KEY_TYPE, CKK_RSA);
            publicKeyValueTemplate[2].setAttr(CKA_MODULUS, dropPrecedingZeros(publicKey.getModulus().toByteArray()));
            publicKeyValueTemplate[3].setAttr(CKA_PUBLIC_EXPONENT, publicKey.getPublicExponent().toByteArray());
        } else if (x509certificate.getPublicKey().getAlgorithm().equals("EC")) {
            BCECPublicKey publicKey =
                    new BCECPublicKey((ECPublicKey) x509certificate.getPublicKey(), BouncyCastleProvider.CONFIGURATION);

            println("Finding public key by ecliptic curve point");
            publicKeyValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(3);
            publicKeyValueTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
            publicKeyValueTemplate[1].setAttr(CKA_KEY_TYPE, CKK_EC);
            publicKeyValueTemplate[2].setAttr(CKA_EC_POINT,
                    new DEROctetString(publicKey.getQ().getEncoded(false)).getEncoded());
        } else { // gost
            println("Decode public key from ASN.1 structure");
            ASN1Sequence sequence = ASN1Sequence.getInstance(x509certificate.getPublicKey().getEncoded());
            byte[] publicKeyValue = ASN1OctetString.getInstance(((ASN1BitString) sequence.getObjectAt(1)).getOctets())
                    .getOctets();
            printHex("Public key value is:", publicKeyValue);

            println("Finding public key by value");
            publicKeyValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(2);
            publicKeyValueTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
            publicKeyValueTemplate[1].setAttr(CKA_VALUE, publicKeyValue);
        }

        NativeLong publicKey = findFirstObject(pkcs11, session, publicKeyValueTemplate);

        // Using public key we can find private key handle
        println("Getting public key ID");
        CK_ATTRIBUTE[] publicKeyIdTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        publicKeyIdTemplate[0].setAttr(CKA_ID, null, 0);
        getAttributeValues(pkcs11, session, publicKey, publicKeyIdTemplate);

        println("Finding private key by public key ID");
        CK_ATTRIBUTE[] privateKeyTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(2);
        privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
        privateKeyTemplate[1].setAttr(publicKeyIdTemplate[0].type, publicKeyIdTemplate[0].pValue,
                publicKeyIdTemplate[0].ulValueLen);
        NativeLong privateKey = findFirstObject(pkcs11, session, privateKeyTemplate);

        return new KeyPair(publicKey, privateKey);
    }

    public static byte[] deriveEcdhKey(Pkcs11 pkcs11, long sessionHandle, byte[] publicKeyBytes, long privateKeyHandle,
                                       CK_ATTRIBUTE[] derivedKeyTemplate) throws Pkcs11Exception {
        CK_ECDH1_DERIVE_PARAMS deriveParameters =
                new CK_ECDH1_DERIVE_PARAMS(new NativeLong(CKD_NULL), publicKeyBytes, null);
        deriveParameters.write(); // writes the fields of the structure to native memory

        CK_MECHANISM deriveMechanism =
                new CK_MECHANISM(CKM_ECDH1_DERIVE, deriveParameters.getPointer(), deriveParameters.size());

        NativeLongByReference derivedKey = new NativeLongByReference();
        NativeLong rv =
                pkcs11.C_DeriveKey(new NativeLong(sessionHandle), deriveMechanism, new NativeLong(privateKeyHandle),
                        derivedKeyTemplate, new NativeLong(derivedKeyTemplate.length), derivedKey);
        Pkcs11Exception.throwIfNotOk("C_DeriveKey failed", rv);

        return Pkcs11Operations.getKeyValue(pkcs11, new NativeLong(sessionHandle), derivedKey.getValue());
    }

    private static byte[] dropPrecedingZeros(byte[] array) {
        if (array.length == 0)
            return array;

        int numPrecedingZeros = 0;
        for (int i = 0; i < array.length; i++)
            if (array[i] != 0) {
                numPrecedingZeros = i;
                break;
            }
        return Arrays.copyOfRange(array, numPrecedingZeros, array.length);
    }
}
