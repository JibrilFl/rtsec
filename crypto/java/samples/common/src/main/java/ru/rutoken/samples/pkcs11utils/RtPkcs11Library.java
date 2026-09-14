/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import java.util.Collections;
import java.util.List;

import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.utils.AbstractNativeLibrary;

public class RtPkcs11Library extends AbstractNativeLibrary<RtPkcs11> {
    private static final RtPkcs11 INSTANCE = new RtPkcs11Library().load();

    @Override
    protected String getTempDirName() {
        return "rtpkcs11ecp-tmp";
    }

    @Override
    protected Class<RtPkcs11> getInterfaceClass() {
        return RtPkcs11.class;
    }

    @Override
    protected List<NativeComponent> getDependencyComponents() {
        return Collections.emptyList();
    }

    @Override
    protected NativeComponent getMainComponent() {
        return new NativeComponent.Builder().setDefaultName("rtpkcs11ecp").build();
    }

    public static Pkcs11 getPkcs11Interface() {
        return INSTANCE;
    }

    public static RtPkcs11 getPkcs11ExtendedInterface() {
        return INSTANCE;
    }
}
