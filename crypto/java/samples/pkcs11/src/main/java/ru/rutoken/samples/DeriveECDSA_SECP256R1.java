/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_ECDH1_DERIVE_PARAMS;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11TokenUtils;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_CLASS;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_DERIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_EXTRACTABLE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_KEY_TYPE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_LABEL;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_PRIVATE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_SENSITIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_TOKEN;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKD_NULL;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_EC;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_GENERIC_SECRET;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_ECDH1_DERIVE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_PRIVATE_KEY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_SECRET_KEY;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_INVALID_HANDLE;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;
import static ru.rutoken.samples.utils.Util.RECIPIENT_ECDSA_SECP256R1_PUBLIC_KEY;

/**
 * Sample of deriving a key from ECDSA key pair with secp256r1 curve and recipient ECDSA public key.
 * Expects key pair on token, you should run {@link CreateKeyPairAndCertificateECDSA_SECP256R1} sample to create it.
 */
public class DeriveECDSA_SECP256R1 {
    /**
     * Template for finding private key
     */
    private final static CK_ATTRIBUTE[] privateKeyTemplate;
    private final static CK_ATTRIBUTE[] derivedKeyTemplate;

    static {
        privateKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
        privateKeyTemplate[1].setAttr(CKA_ID, CreateKeyPairAndCertificateECDSA_SECP256R1.KEY_PAIR_ID);
        privateKeyTemplate[2].setAttr(CKA_KEY_TYPE, CKK_EC);
        privateKeyTemplate[3].setAttr(CKA_DERIVE, true); // Key supports key exchange (VKO)

        derivedKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(7);
        derivedKeyTemplate[0].setAttr(CKA_LABEL, "Derived Secret key");
        derivedKeyTemplate[1].setAttr(CKA_CLASS, CKO_SECRET_KEY);
        derivedKeyTemplate[2].setAttr(CKA_KEY_TYPE, CKK_GENERIC_SECRET);
        derivedKeyTemplate[3].setAttr(CKA_TOKEN, false);
        derivedKeyTemplate[4].setAttr(CKA_PRIVATE, true); // Accessible only after authentication
        derivedKeyTemplate[5].setAttr(CKA_EXTRACTABLE, true); // Key may be extracted in encrypted form
        derivedKeyTemplate[6].setAttr(CKA_SENSITIVE, false); // Key may be extracted in open form
    }

    public static void main(String[] args) {
        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);

        try {
            NativeLong token = CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);

            if (!CommonPkcs11TokenUtils.isMechanismSupported(pkcs11, token, CKM_ECDH1_DERIVE))
                throw new UnsupportedOperationException("Token doesn't support the ECDH derive mechanism.");

            println("Finding private key");
            NativeLong privateKey = CommonPkcs11Operations.findFirstObject(pkcs11, session, privateKeyTemplate);

            println("Deriving key");
            CK_ECDH1_DERIVE_PARAMS deriveParameters =
                    new CK_ECDH1_DERIVE_PARAMS(new NativeLong(CKD_NULL), RECIPIENT_ECDSA_SECP256R1_PUBLIC_KEY, null);

            deriveParameters.write(); // writes the fields of the structure to native memory

            CK_MECHANISM deriveMechanism = new CK_MECHANISM(CKM_ECDH1_DERIVE, deriveParameters.getPointer(),
                    deriveParameters.size());

            NativeLongByReference derivedKey = new NativeLongByReference();

            NativeLong rv = pkcs11.C_DeriveKey(session, deriveMechanism, privateKey, derivedKeyTemplate,
                    new NativeLong(derivedKeyTemplate.length), derivedKey);
            Pkcs11Exception.throwIfNotOk("C_DeriveKey failed", rv);

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }
}
