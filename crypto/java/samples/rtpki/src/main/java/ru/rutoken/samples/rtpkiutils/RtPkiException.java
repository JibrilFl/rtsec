/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.rtpkiutils;

import ru.rutoken.rtpki.RtPkiResult;

public class RtPkiException extends Exception {
    public RtPkiException(String message) {
        super(message);
    }

    public static void throwIfNotOk(String function, int code) throws RtPkiException {
        if (RtPkiResult.RT_PKI_OK != code)
            throw new RtPkiException(function + " failed, error code: 0x" + Integer.toHexString(code));
    }
}
