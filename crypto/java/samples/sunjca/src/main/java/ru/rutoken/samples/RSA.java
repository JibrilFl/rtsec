package ru.rutoken.samples;

import ru.rutoken.samples.pkcs11utils.CommonConstants;

import javax.crypto.Cipher;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import static ru.rutoken.samples.Utils.*;
import static ru.rutoken.samples.utils.CommonUtil.*;

/**
 * Sample of working with RSA algorithm using SunPKCS11 Provider via JCA.
 * This sample requires an empty token or a token with RSA containers (key pair + certificate) only.
 */
public class RSA {
    /**
     * To change RSA module size, edit this value and the CKA_MODULUS_BITS parameter in configuration file.
     * For example, to generate an RSA-4096 key pair, both parameters must be 4096.
     */
    private static final int RSA_KEY_SIZE = 2048;

    public static void main(String[] args) {
        try {
            Provider provider = initializeProvider();

            println("Token authorization");
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            keyStore.load(null, new String(CommonConstants.DEFAULT_USER_PIN).toCharArray());

            PublicKey publicKey = null;
            PrivateKey privateKey = null;

            // Finding key pair on token (only if a related certificate exists)
            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                if (certificate == null)
                    continue;

                println("Certificate:\n " + certificate);
                publicKey = certificate.getPublicKey();
                privateKey = (PrivateKey) keyStore.getKey(alias, null);
                break;
            }

            if (publicKey == null || privateKey == null) {
                println("Key pair generation");
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);
                generator.initialize(RSA_KEY_SIZE);
                KeyPair pair = generator.generateKeyPair();
                publicKey = pair.getPublic();
                privateKey = pair.getPrivate();
            }

            println("Public key:\n " + publicKey);
            println("Private key:\n " + privateKey);

            println("Encrypting data");
            Cipher rsaEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
            // If the keypair was not generated in the sample then public key is implicitly imported
            // by JCA with C_CreateObject() on this call. Key template can be customized with import
            // template in pkcs11.cfg.
            rsaEncrypt.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] dataToEncrypt = Constants.MESSAGE;

            // As the Cipher uses padding, the length of the message we encrypt is shorter than key size
            byte[] encryptedData = rsaEncrypt.doFinal(dataToEncrypt);

            printHex("Encrypted data:", encryptedData);
            println("Data has been encrypted successfully.\n");

            println("Decrypting data");
            Cipher rsaDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
            rsaDecrypt.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = rsaDecrypt.doFinal(encryptedData);
            printHex("Decrypted data:", decryptedData);

            if (!Arrays.equals(dataToEncrypt, decryptedData))
                throw new RuntimeException("Decrypted data does not match original");
            println("Data has been decrypted successfully.\n");

            println("Signing data");
            byte[] dataToSign = Constants.MESSAGE;

            Signature rsaSign = Signature.getInstance("SHA1withRSA", provider);
            rsaSign.initSign(privateKey);
            rsaSign.update(dataToSign);
            byte[] signedData = rsaSign.sign();

            printHex("Signed data:", signedData);
            println("Data has been signed successfully.");

            println("Verifying signature");
            Signature rsaVerify = Signature.getInstance("SHA1withRSA", provider);
            rsaVerify.initVerify(publicKey);
            rsaVerify.update(dataToSign);
            if (!rsaVerify.verify(signedData))
                throw new RuntimeException("Signature verification failed!");
            println("Signature has been verified successfully.");

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        }
    }
}
