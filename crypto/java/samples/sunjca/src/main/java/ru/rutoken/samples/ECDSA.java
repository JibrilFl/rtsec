/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import ru.rutoken.samples.pkcs11utils.CommonConstants;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static ru.rutoken.samples.Utils.*;
import static ru.rutoken.samples.utils.CommonUtil.*;

/**
 * Sample of working with ECDSA algorithm using SunPKCS11 Provider via JCA.
 * This sample requires a token with ECDSA support.
 */
public class ECDSA {
    /**
     * Set ECDSA curve name here.
     */
    private static final String CURVE_NAME = "secp256r1";

    public static void main(String[] args) {
        try {
            Provider provider = initializeProvider();

            println("Token authorization");
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            keyStore.load(null, new String(CommonConstants.DEFAULT_USER_PIN).toCharArray());

            println("Key pair generation");
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", provider);
            keygen.initialize(new ECGenParameterSpec(CURVE_NAME));

            KeyPair pair = keygen.generateKeyPair();
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            println("Public key:\n " + publicKey);
            println("Private key:\n " + privateKey);

            println("Signing data");
            byte[] dataToSign = Constants.MESSAGE;

            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", provider);
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(dataToSign);
            byte[] signedData = ecdsaSign.sign();

            printHex("Signed data:", signedData);
            println("Data has been signed successfully.");

            println("Verifying signature");
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", provider);
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(dataToSign);
            if (!ecdsaVerify.verify(signedData))
                throw new RuntimeException("Signature verification failed!");
            println("Signature has been verified successfully.");

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        }
    }
}
