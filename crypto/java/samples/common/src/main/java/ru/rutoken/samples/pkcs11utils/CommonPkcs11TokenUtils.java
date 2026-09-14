/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

/**
 * Common operations on PKCS#11 token
 */
public final class CommonPkcs11TokenUtils {
    private CommonPkcs11TokenUtils() {
    }

    public static boolean isMechanismSupported(Pkcs11 pkcs11, NativeLong slot, long mechanism) {
        try {
            NativeLong[] mechanisms = CommonPkcs11Operations.getMechanismList(pkcs11, slot);
            for (NativeLong m : mechanisms) {
                if (Pkcs11Constants.equalsPkcsRV(mechanism, m))
                    return true;
            }
        } catch (Pkcs11Exception e) {
            return false;
        }

        return false;
    }
}
