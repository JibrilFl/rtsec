/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import ru.rutoken.samples.pkcs11utils.CommonConstants;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static ru.rutoken.samples.Utils.*;
import static ru.rutoken.samples.utils.CommonUtil.*;

/**
 * Sample of working with ECDH algorithm using SunPKCS11 Provider via JCA.
 * This sample requires a token with ECDSA and ECDH support.
 */
public class ECDH {
    /**
     * Set ECDH curve name here.
     */
    private static final String CURVE_NAME = "secp256r1";

    public static void main(String[] args) {
        try {
            Provider provider = initializeProvider();

            println("Token authorization");
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            keyStore.load(null, new String(CommonConstants.DEFAULT_USER_PIN).toCharArray());

            println("Generating key pairs for both parties");
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", provider);
            keygen.initialize(new ECGenParameterSpec(CURVE_NAME));

            KeyPair party1KeyPair = keygen.generateKeyPair();
            KeyPair party2KeyPair = keygen.generateKeyPair();

            PublicKey party1PublicKey = party1KeyPair.getPublic();
            PrivateKey party1PrivateKey = party1KeyPair.getPrivate();

            PublicKey party2PublicKey = party2KeyPair.getPublic();
            PrivateKey party2PrivateKey = party2KeyPair.getPrivate();

            println("Party 1 Public Key:\n " + party1PublicKey);
            println("Party 2 Public Key:\n " + party2PublicKey);

            println("Establishing shared secret for both parties");

            KeyAgreement party1KeyAgree = KeyAgreement.getInstance("ECDH", provider);
            party1KeyAgree.init(party1PrivateKey);
            party1KeyAgree.doPhase(party2PublicKey, true);
            byte[] party1SharedSecret = party1KeyAgree.generateSecret();

            KeyAgreement party2KeyAgree = KeyAgreement.getInstance("ECDH", provider);
            party2KeyAgree.init(party2PrivateKey);
            party2KeyAgree.doPhase(party1PublicKey, true);
            byte[] party2SharedSecret = party2KeyAgree.generateSecret();

            if (!Arrays.equals(party1SharedSecret, party2SharedSecret)) {
                throw new RuntimeException("Shared secrets do not match!");
            }

            println("Shared secret established successfully");

            // We construct AES-128 secret key to match secp256k1, secp256r1, secp384r1 and secp521r1 curve sizes.
            SecretKey encryptionKeyParty1 = new SecretKeySpec(party1SharedSecret, 0, 16, "AES");
            SecretKey encryptionKeyParty2 = new SecretKeySpec(party2SharedSecret, 0, 16, "AES");

            printHex("Encryption key derived by Party 1: ", encryptionKeyParty1.getEncoded());
            printHex("Encryption key derived by Party 2: ", encryptionKeyParty2.getEncoded());

            println("Encrypting data using Party 1's key");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKeyParty1);

            byte[] dataToEncrypt = Constants.MESSAGE;
            printHex("Original data: ", dataToEncrypt);

            byte[] encryptedData = cipher.doFinal(dataToEncrypt);
            printHex("Encrypted data: ", encryptedData);

            println("Decrypting data using Party 2's key");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKeyParty2);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            printHex("Decrypted data: ", decryptedData);

            if (Arrays.equals(dataToEncrypt, decryptedData)) {
                println("Success: Decrypted data matches the original");
            } else {
                throw new RuntimeException("Failure: Decrypted data does not match the original");
            }

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        }
    }
}
