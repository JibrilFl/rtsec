/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples;

import java.security.Provider;
import java.security.Security;

import static ru.rutoken.samples.utils.CommonUtil.println;

public class Utils {
    public static Provider initializeProvider() {
        String config = "sunjca/cfg/pkcs11.cfg";
        // For Java 8 we use the following API to configure a provider:
        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html#Config
        Provider provider = new sun.security.pkcs11.SunPKCS11(config);
        // To build the sample with Java 11, comment the line above and uncomment the two lines below, as
        // the API has changed. See https://docs.oracle.com/javase/9/security/pkcs11-reference-guide1.htm
        // Provider provider = Security.getProvider("SunPKCS11");
        // provider = provider.configure(config);

        int position = Security.addProvider(provider);
        println("Provider preference position: " + position);
        return provider;
    }
}
