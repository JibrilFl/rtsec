/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11jna.CK_MECHANISM_INFO;
import ru.rutoken.pkcs11jna.Pkcs11;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_EC_KEY_PAIR_GEN;

public final class Pkcs11TokenUtils {
    private static final int ECDSA_SECP_384_KEY_SIZE = 384;

    private Pkcs11TokenUtils() {
    }

    public static boolean isLongEcdsaCurvesSupported(Pkcs11 pkcs11, NativeLong slot) {
        try {
            CK_MECHANISM_INFO mechanismInfo = Pkcs11Operations.getMechanismInfo(pkcs11, slot, CKM_EC_KEY_PAIR_GEN);
            return mechanismInfo.ulMaxKeySize.intValue() >= ECDSA_SECP_384_KEY_SIZE;
        } catch (Pkcs11Exception e) {
            return false;
        }
    }
}
