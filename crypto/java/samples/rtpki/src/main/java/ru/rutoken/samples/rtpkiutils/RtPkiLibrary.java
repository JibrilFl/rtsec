/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.rtpkiutils;

import java.util.Arrays;
import java.util.List;

import ru.rutoken.rtpki.RtPki;
import ru.rutoken.samples.utils.AbstractNativeLibrary;

public class RtPkiLibrary extends AbstractNativeLibrary<RtPki> {
    private static final RtPki INSTANCE = new RtPkiLibrary().load();

    @Override
    protected String getTempDirName() {
        return "rtpki-tmp";
    }

    @Override
    protected Class<RtPki> getInterfaceClass() {
        return RtPki.class;
    }

    @Override
    protected List<NativeComponent> getDependencyComponents() {
        return Arrays.asList(
                new NativeComponent.Builder()
                        .setDefaultName("crypto")
                        .setDarwinName("libcrypto")
                        .setWindowsX86Name("libcrypto-3")
                        .setWindowsX86_64Name("libcrypto-3-x64")
                        .build(),
                new NativeComponent.Builder().setDefaultName("rtengine").build()
        );
    }

    @Override
    protected NativeComponent getMainComponent() {
        return new NativeComponent.Builder().setDefaultName("rtpki").build();
    }

    public static RtPki getRtPkiInterface() {
        return INSTANCE;
    }
}
