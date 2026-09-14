/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

public final class Constants {
    public static final byte[] ATTR_CRYPTO_PRO_A_GOST28147_89 =
            {0x06, 0x07, 0x2A, (byte) 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01};
    public static final byte[] ATTR_CRYPTO_PRO_A_GOSTR3410_2001 =
            {0x06, 0x07, 0x2A, (byte) 0x85, 0x03, 0x02, 0x02, 0x23, 0x01};
    public static final byte[] ATTR_CRYPTO_PRO_A_GOSTR3410_2012_256 = ATTR_CRYPTO_PRO_A_GOSTR3410_2001;
    public static final byte[] ATTR_CRYPTO_PRO_A_GOSTR3410_2012_512 =
            {0x06, 0x09, 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01};

    public final static byte[] ATTR_GOSTR3411_1994 = {0x06, 0x07, 0x2a, (byte) 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01};
    public final static byte[] ATTR_GOSTR3411_2012_256 =
            {0x06, 0x08, 0x2a, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};
    public final static byte[] ATTR_GOSTR3411_2012_512 =
            {0x06, 0x08, 0x2a, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03};

    public final static byte[] ATTR_ECDSA_SECP256R1 =
            {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    public final static byte[] ATTR_ECDSA_SECP256K1 = {0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x0a};
    public final static byte[] ATTR_ECDSA_SECP384R1 = {0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x22};
    public final static byte[] ATTR_ECDSA_SECP521R1 = {0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x23};

    private Constants() {
    }
}
