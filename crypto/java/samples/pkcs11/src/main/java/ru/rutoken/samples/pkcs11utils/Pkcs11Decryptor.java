/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;

public class Pkcs11Decryptor {
    private final long mSessionHandle;

    public Pkcs11Decryptor(long sessionHandle) {
        mSessionHandle = sessionHandle;
    }

    public byte[] decrypt(byte[] data, CK_MECHANISM decryptMechanism, long keyHandle) throws Pkcs11Exception {
        final Pkcs11 pkcs11 = RtPkcs11Library.getPkcs11Interface();

        NativeLong rv = pkcs11.C_DecryptInit(new NativeLong(mSessionHandle), decryptMechanism,
                new NativeLong(keyHandle));
        Pkcs11Exception.throwIfNotOk("C_DecryptInit failed", rv);

        NativeLongByReference decryptedSize = new NativeLongByReference(new NativeLong(data.length));
        rv = pkcs11.C_Decrypt(new NativeLong(mSessionHandle), data, new NativeLong(data.length), null, decryptedSize);
        Pkcs11Exception.throwIfNotOk("C_Decrypt failed", rv);

        byte[] decrypted = new byte[decryptedSize.getValue().intValue()];
        rv = pkcs11.C_Decrypt(new NativeLong(mSessionHandle), data, new NativeLong(data.length), decrypted,
                decryptedSize);
        Pkcs11Exception.throwIfNotOk("C_Decrypt failed", rv);

        return decrypted;
    }
}
