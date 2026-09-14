/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.pkcs11utils.CK_GOSTR3410_DERIVE_PARAMS_JRT;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.utils.CommonUtil.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Sample of deriving a key from GOST R 34.10-2001 key pair and recipient public key.
 * Expects key pair on token, you should run {@link CreateKeyPairAndCertificateGOSTR3410_2001} sample to create it.
 */
public class DeriveGOSTR3410_2001 {
    private final static long CKD_CPDIVERSIFY_KDF_JRT = 0x90000009;
    private final static int UKM_LENGTH = 8;

    /**
     * Template for finding private key
     */
    private final static CK_ATTRIBUTE[] privateKeyTemplate;
    private final static CK_ATTRIBUTE[] derivedKeyTemplate;

    static {
        privateKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(4);
        privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
        privateKeyTemplate[1].setAttr(CKA_ID, CreateKeyPairAndCertificateGOSTR3410_2001.KEY_PAIR_ID);
        privateKeyTemplate[2].setAttr(CKA_KEY_TYPE, CKK_GOSTR3410);
        privateKeyTemplate[3].setAttr(CKA_DERIVE, true); // Key supports key exchange (VKO)

        derivedKeyTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(8);
        derivedKeyTemplate[0].setAttr(CKA_LABEL, "Derived GOST 28147-89 key");
        derivedKeyTemplate[1].setAttr(CKA_CLASS, CKO_SECRET_KEY);
        derivedKeyTemplate[2].setAttr(CKA_KEY_TYPE, CKK_GOST28147);
        derivedKeyTemplate[3].setAttr(CKA_TOKEN, false);
        derivedKeyTemplate[4].setAttr(CKA_MODIFIABLE, true);
        derivedKeyTemplate[5].setAttr(CKA_PRIVATE, true); // Accessible only after authentication
        derivedKeyTemplate[6].setAttr(CKA_EXTRACTABLE, true); // Key may be extracted in encrypted form
        derivedKeyTemplate[7].setAttr(CKA_SENSITIVE, false); // Key may be extracted in open form
    }

    public static void main(String[] args) {
        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        try {
            CommonPkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, session);

            println("Finding private key");
            NativeLong privateKey = CommonPkcs11Operations.findFirstObject(pkcs11, session, privateKeyTemplate);

            println("Deriving key");
            byte[] deriveParamUkm = generateRandom(UKM_LENGTH);

            CK_GOSTR3410_DERIVE_PARAMS_JRT deriveParameters = new CK_GOSTR3410_DERIVE_PARAMS_JRT(
                    new NativeLong(CKD_CPDIVERSIFY_KDF_JRT), new NativeLong(RECIPIENT_GOST_PUBLIC_KEY_256.length),
                    RECIPIENT_GOST_PUBLIC_KEY_256, new NativeLong(deriveParamUkm.length), deriveParamUkm);

            deriveParameters.write(); // writes the fields of the structure to native memory

            CK_MECHANISM deriveMechanism = new CK_MECHANISM(CKM_GOSTR3410_DERIVE, deriveParameters.getPointer(),
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
