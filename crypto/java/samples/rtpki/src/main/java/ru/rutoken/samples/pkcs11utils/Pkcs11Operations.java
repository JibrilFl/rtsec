/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_ID;
import static ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations.getAttributeValues;

public class Pkcs11Operations {
    private Pkcs11Operations() {
    }

    public static byte[] getCertificateId(Pkcs11 pkcs11, NativeLong session, NativeLong certificate)
            throws Pkcs11Exception {
        CK_ATTRIBUTE[] certificateIdTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        certificateIdTemplate[0].setAttr(CKA_ID, null, 0);
        getAttributeValues(pkcs11, session, certificate, certificateIdTemplate);
        return certificateIdTemplate[0].pValue.getByteArray(0, certificateIdTemplate[0].ulValueLen.intValue());
    }
}
