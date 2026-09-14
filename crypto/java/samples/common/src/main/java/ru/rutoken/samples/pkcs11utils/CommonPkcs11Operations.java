/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_C_INITIALIZE_ARGS;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO;
import ru.rutoken.pkcs11jna.Pkcs11;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKA_VALUE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKF_OS_LOCKING_OK;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKF_RW_SESSION;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKF_SERIAL_SESSION;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CKU_USER;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_FALSE;
import static ru.rutoken.pkcs11jna.Pkcs11Constants.CK_TRUE;
import static ru.rutoken.samples.utils.CommonUtil.checkIfNotOk;
import static ru.rutoken.samples.utils.CommonUtil.println;

/**
 * Common operations on PKCS#11
 */
public final class CommonPkcs11Operations {
    private CommonPkcs11Operations() {
    }

    public static NativeLong initializePkcs11AndGetFirstToken(Pkcs11 pkcs11) throws Pkcs11Exception {
        CK_C_INITIALIZE_ARGS initializeArgs = new CK_C_INITIALIZE_ARGS(
                null, null, null, null,
                new NativeLong(CKF_OS_LOCKING_OK), null);

        NativeLong rv = pkcs11.C_Initialize(initializeArgs);
        Pkcs11Exception.throwIfNotOk("C_Initialize failed", rv);

        NativeLong[] slots = getSlotList(pkcs11, true);
        if (slots.length == 0)
            throw new IllegalStateException("Rutoken is not found");

        println("Getting info about tokens");
        // You can select appropriate token by serial number
        List<CK_TOKEN_INFO> tokenInfos = getTokenInfos(pkcs11, slots);
        for (CK_TOKEN_INFO tokenInfo : tokenInfos) {
            println("Token serial: " + new String(tokenInfo.serialNumber));
        }
        // We'll just take the first one for simplicity
        return slots[0];
    }

    public static NativeLong initializePkcs11AndLoginToFirstToken(Pkcs11 pkcs11, NativeLong session)
            throws Pkcs11Exception {
        NativeLong token = initializePkcs11AndGetFirstToken(pkcs11);

        NativeLongByReference sessionPointer = new NativeLongByReference();
        NativeLong rv = pkcs11.C_OpenSession(token, new NativeLong(CKF_SERIAL_SESSION | CKF_RW_SESSION),
                null, null, sessionPointer);
        Pkcs11Exception.throwIfNotOk("C_OpenSession failed", rv);
        session.setValue(sessionPointer.getValue().longValue());

        rv = pkcs11.C_Login(session, new NativeLong(CKU_USER), CommonConstants.DEFAULT_USER_PIN,
                new NativeLong(CommonConstants.DEFAULT_USER_PIN.length));
        Pkcs11Exception.throwIfNotOk("C_Login failed", rv);

        return token;
    }

    public static void logoutAndFinalizePkcs11Library(Pkcs11 pkcs11, NativeLong session) {
        NativeLong rv = pkcs11.C_Logout(session);
        checkIfNotOk("C_Logout failed", rv);

        rv = pkcs11.C_CloseSession(session);
        checkIfNotOk("C_CloseSession failed", rv);

        rv = pkcs11.C_Finalize(null);
        checkIfNotOk("C_Finalize failed", rv);
    }

    public static NativeLong[] getSlotList(Pkcs11 pkcs11, boolean tokenPresent) throws Pkcs11Exception {
        byte presentFlag = tokenPresent ? CK_TRUE : CK_FALSE;
        NativeLongByReference slotsCount = new NativeLongByReference();
        NativeLong rv = pkcs11.C_GetSlotList(presentFlag, null, slotsCount);
        Pkcs11Exception.throwIfNotOk("C_GetSlotList failed", rv);

        if (0 == slotsCount.getValue().intValue())
            return new NativeLong[0];

        NativeLong[] slotList = new NativeLong[slotsCount.getValue().intValue()];
        rv = pkcs11.C_GetSlotList(presentFlag, slotList, slotsCount);
        Pkcs11Exception.throwIfNotOk("C_GetSlotList failed", rv);
        return slotList;
    }

    public static NativeLong[] getMechanismList(Pkcs11 pkcs11, NativeLong slot) throws Pkcs11Exception {
        final NativeLongByReference mechanismsCount = new NativeLongByReference();
        NativeLong rv = pkcs11.C_GetMechanismList(slot, null, mechanismsCount);
        Pkcs11Exception.throwIfNotOk("C_GetMechanismList failed", rv);

        if (0 == mechanismsCount.getValue().intValue())
            return new NativeLong[0];

        NativeLong[] mechanisms = new NativeLong[mechanismsCount.getValue().intValue()];
        rv = pkcs11.C_GetMechanismList(slot, mechanisms, mechanismsCount);
        Pkcs11Exception.throwIfNotOk("C_GetMechanismList failed", rv);

        return mechanisms;
    }

    public static List<CK_TOKEN_INFO> getTokenInfos(Pkcs11 pkcs11, NativeLong[] slots) throws Pkcs11Exception {
        List<CK_TOKEN_INFO> tokenInfos = new ArrayList<>();
        for (NativeLong slot : slots) {
            CK_TOKEN_INFO ckTokenInfo = new CK_TOKEN_INFO();
            NativeLong rv = pkcs11.C_GetTokenInfo(slot, ckTokenInfo);
            Pkcs11Exception.throwIfNotOk("C_GetTokenInfo failed", rv);
            tokenInfos.add(ckTokenInfo);
        }
        return tokenInfos;
    }

    public static NativeLong[] findObjects(Pkcs11 pkcs11, NativeLong session, CK_ATTRIBUTE[] template, int maxCount)
            throws Pkcs11Exception {
        NativeLong rv = pkcs11.C_FindObjectsInit(session, template, new NativeLong(template.length));
        Pkcs11Exception.throwIfNotOk("C_FindObjectsInit failed", rv);
        NativeLong[] objectsBuffer = new NativeLong[maxCount];
        NativeLongByReference pulCount = new NativeLongByReference();
        rv = pkcs11.C_FindObjects(session, objectsBuffer, new NativeLong(objectsBuffer.length), pulCount);
        Pkcs11Exception.throwIfNotOk("C_FindObjects failed", rv);
        rv = pkcs11.C_FindObjectsFinal(session);
        Pkcs11Exception.throwIfNotOk("C_FindObjectsFinal failed", rv);
        return Arrays.copyOf(objectsBuffer, pulCount.getValue().intValue());
    }

    public static void getAttributeValues(Pkcs11 pkcs11, NativeLong session, NativeLong object,
                                          CK_ATTRIBUTE[] attributes) throws Pkcs11Exception {
        NativeLong rv = pkcs11.C_GetAttributeValue(session, object, attributes, new NativeLong(attributes.length));
        Pkcs11Exception.throwIfNotOk("C_GetAttributeValue failed", rv);
        for (CK_ATTRIBUTE attribute : attributes)
            attribute.pValue = new Memory(attribute.ulValueLen.intValue());

        rv = pkcs11.C_GetAttributeValue(session, object, attributes, new NativeLong(attributes.length));
        Pkcs11Exception.throwIfNotOk("C_GetAttributeValue failed", rv);
    }

    public static byte[] getCertificateValue(Pkcs11 pkcs11, NativeLong session, NativeLong certificate)
            throws Pkcs11Exception {
        CK_ATTRIBUTE[] certificateValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        certificateValueTemplate[0].setAttr(CKA_VALUE, null, 0);
        getAttributeValues(pkcs11, session, certificate, certificateValueTemplate);
        return certificateValueTemplate[0].pValue.getByteArray(0, certificateValueTemplate[0].ulValueLen.intValue());
    }

    /**
     * For simplicity, we find first object matching template,
     * in production you should generally check that only single object matches template.
     */
    public static NativeLong findFirstObject(Pkcs11 pkcs11, NativeLong session, CK_ATTRIBUTE[] template)
            throws Pkcs11Exception {
        NativeLong[] objects = findObjects(pkcs11, session, template, 1);
        if (objects.length < 1)
            throw new IllegalStateException("Object not found");
        return objects[0];
    }
}
