/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.utils;

import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11jna.Pkcs11Constants;

public final class CommonUtil {
    private CommonUtil() {
    }

    public static void println(String text) {
        System.out.println(text);
    }

    public static void printlnError(String text) {
        System.err.println(text);
    }

    public static void printString(String label, String data) {
        println(label);
        println(data);
    }

    public static void printHex(String label, byte[] data) {
        println(label);
        printHex(data);
    }

    public static void printHex(byte[] data) {
        for (int i = 0; i < data.length; ++i) {
            System.out.printf(" %02X", data[i]);
            if ((i + 1) % 16 == 0)
                System.out.println();
        }
        System.out.println();
    }

    public static void checkIfNotOk(String function, NativeLong rv) {
        if (!Pkcs11Constants.equalsPkcsRV(Pkcs11Constants.CKR_OK, rv))
            println(function + ", error code: " + Long.toHexString(rv.longValue()));
    }
}
