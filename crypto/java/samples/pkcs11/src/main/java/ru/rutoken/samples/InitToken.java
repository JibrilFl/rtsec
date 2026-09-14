/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.pkcs11utils.CommonConstants.DEFAULT_SO_PIN;
import static ru.rutoken.samples.pkcs11utils.CommonConstants.DEFAULT_USER_PIN;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;

/**
 * Sample of token initialization using rtpkcs11ecp via JNA
 */
public class InitToken {
    private final static byte[] TOKEN_LABEL = {
            'M', 'y', ' ', 'R', 'u', 't', 'o', 'k', 'e', 'n', ' ', ' ', ' ', ' ', ' ', ' ',
            ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '};

    public static void main(String[] args) {
        Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        try {
            NativeLong token = CommonPkcs11Operations.initializePkcs11AndGetFirstToken(pkcs11);

            println("Token initialization");
            NativeLong rv = pkcs11.C_InitToken(token, DEFAULT_SO_PIN, new NativeLong(DEFAULT_SO_PIN.length),
                    TOKEN_LABEL);
            Pkcs11Exception.throwIfNotOk("C_InitToken failed", rv);

            println("Opening session");
            NativeLongByReference sessionRef = new NativeLongByReference();
            rv = pkcs11.C_OpenSession(token, new NativeLong(CKF_SERIAL_SESSION | CKF_RW_SESSION),
                    null, null, sessionRef);
            Pkcs11Exception.throwIfNotOk("C_OpenSession failed", rv);
            session = sessionRef.getValue();

            println("Logging in as administrator");
            rv = pkcs11.C_Login(session, new NativeLong(CKU_SO), DEFAULT_SO_PIN, new NativeLong(DEFAULT_SO_PIN.length));
            Pkcs11Exception.throwIfNotOk("C_Login failed", rv);

            println("User PIN initialization");
            rv = pkcs11.C_InitPIN(session, DEFAULT_USER_PIN, new NativeLong(DEFAULT_USER_PIN.length));
            Pkcs11Exception.throwIfNotOk("C_InitPIN failed", rv);

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }
}
