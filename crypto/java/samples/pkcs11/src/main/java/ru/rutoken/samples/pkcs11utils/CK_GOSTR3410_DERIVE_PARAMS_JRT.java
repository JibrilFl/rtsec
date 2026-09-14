/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11jna.Pkcs11Structure;

import java.util.Arrays;
import java.util.List;

public class CK_GOSTR3410_DERIVE_PARAMS_JRT extends Pkcs11Structure {
    public NativeLong kdf;
    public NativeLong ulPublicDataLen;
    public byte[] pPublicData = new byte[64];
    public NativeLong ulUKMLen;
    public byte[] pUKM = new byte[8];

    public CK_GOSTR3410_DERIVE_PARAMS_JRT() {
    }

    public CK_GOSTR3410_DERIVE_PARAMS_JRT(NativeLong kdf, NativeLong publicKeyLen, byte[] publicKey,
                                          NativeLong ukmLen, byte[] ukm) {
        this.kdf = kdf;
        this.ulPublicDataLen = publicKeyLen;
        this.pPublicData = publicKey;
        this.ulUKMLen = ukmLen;
        this.pUKM = ukm;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList(
                "kdf",
                "ulPublicDataLen",
                "pPublicData",
                "ulUKMLen",
                "pUKM"
        );
    }
}