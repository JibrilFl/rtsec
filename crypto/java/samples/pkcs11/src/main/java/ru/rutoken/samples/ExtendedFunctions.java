package ru.rutoken.samples;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import ru.rutoken.pkcs11jna.CK_RUTOKEN_INIT_PARAM;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO_EXTENDED;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.pkcs11utils.CommonPkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Exception;
import ru.rutoken.samples.pkcs11utils.RtPkcs11Library;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.pkcs11jna.RtPkcs11Constants.*;
import static ru.rutoken.samples.pkcs11utils.CommonConstants.DEFAULT_SO_PIN;
import static ru.rutoken.samples.pkcs11utils.CommonConstants.DEFAULT_USER_PIN;
import static ru.rutoken.samples.utils.CommonUtil.println;
import static ru.rutoken.samples.utils.CommonUtil.printlnError;

/**
 * Sample of rtpkcs11ecp extended functions usage via JNA
 */
public class ExtendedFunctions {
    private final static byte[] NEW_PIN = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    private final static String TOKEN_LABEL = "It is my Rutoken label sample ";
    private final static String TOKEN_LONG_LABEL = "!!!Sample of Rutoken long-long-long-long-long label!!!";
    private final static int MAX_ADMIN_RETRY_COUNT = 10;
    private final static int MAX_USER_RETRY_COUNT = 10;

    public static void main(String[] args) {
        RtPkcs11 pkcs11 = RtPkcs11Library.getPkcs11ExtendedInterface();
        NativeLong session = new NativeLong(CK_INVALID_HANDLE);
        try {
            NativeLong token = CommonPkcs11Operations.initializePkcs11AndGetFirstToken(pkcs11);

            println("Acquiring token extended info");
            CK_TOKEN_INFO_EXTENDED tokenInfoEx = new CK_TOKEN_INFO_EXTENDED();
            tokenInfoEx.ulSizeofThisStructure = new NativeLong(tokenInfoEx.size());
            NativeLong rv = pkcs11.C_EX_GetTokenInfoExtended(token, tokenInfoEx);
            Pkcs11Exception.throwIfNotOk("C_EX_GetTokenInfoExtended failed", rv);

            println("Token info:");
            System.out.printf(" Token class:\t\t\t\t0x%08X ", tokenInfoEx.ulTokenClass.longValue());
            if (tokenInfoEx.ulTokenClass.longValue() == TOKEN_CLASS_ECP)
                println("(Rutoken ECP)");
            else if (tokenInfoEx.ulTokenClass.longValue() == TOKEN_CLASS_LITE)
                println("(Rutoken Lite)");
            else if (tokenInfoEx.ulTokenClass.longValue() == TOKEN_CLASS_S)
                println("(Rutoken)");
            else
                System.out.println();

            System.out.printf(" Protocol number: \t\t\t0x%08X \n", tokenInfoEx.ulProtocolNumber.longValue());
            System.out.printf(" Microcode number:  \t\t0x%08X \n", tokenInfoEx.ulMicrocodeNumber.longValue());
            System.out.printf(" Flags: \t\t\t\t\t0x%08X\n", tokenInfoEx.flags.longValue());
            System.out.printf(" Min Admin PIN length: \t\t0x%08X \n", tokenInfoEx.ulMinAdminPinLen.longValue());
            System.out.printf(" Max User PIN length: \t\t0x%08X\n", tokenInfoEx.ulMaxUserPinLen.longValue());
            System.out.printf(" Min User PIN length: \t\t0x%08X\n", tokenInfoEx.ulMinUserPinLen.longValue());
            System.out.printf(" Max Admin login failures: \t0x%08X \n", tokenInfoEx.ulMaxAdminRetryCount.longValue());
            System.out.printf(" Admin login failures: \t\t0x%08X \n", tokenInfoEx.ulAdminRetryCountLeft.longValue());
            System.out.printf(" Max User login failures: \t0x%08X \n", tokenInfoEx.ulMaxUserRetryCount.longValue());
            System.out.printf(" User login failures: \t\t0x%08X \n", tokenInfoEx.ulUserRetryCountLeft.longValue());
            System.out.print(" Token SN: \t\t\t\t\t0x");
            for (int i = 4; i < tokenInfoEx.serialNumber.length; ++i)
                System.out.printf("%02X", tokenInfoEx.serialNumber[i]);
            System.out.println();
            System.out.printf(" Total memory: \t\t\t\t0x%08X\n", tokenInfoEx.ulTotalMemory.longValue());
            System.out.printf(" Free  memory: \t\t\t\t0x%08X\n", tokenInfoEx.ulFreeMemory.longValue());
            System.out.print(" ATR: \t\t\t\t\t\t");
            for (int i = 0; i < tokenInfoEx.ulATRLen.longValue(); ++i)
                System.out.printf("%02X", tokenInfoEx.ATR[i]);

            println("\nToken initialization");
            CK_RUTOKEN_INIT_PARAM initParam = new CK_RUTOKEN_INIT_PARAM();
            initParam.UseRepairMode = new NativeLong(0);
            initParam.pNewAdminPin = new Memory(DEFAULT_SO_PIN.length);
            initParam.pNewAdminPin.write(0, DEFAULT_SO_PIN, 0, DEFAULT_SO_PIN.length);
            initParam.ulNewAdminPinLen = new NativeLong(DEFAULT_SO_PIN.length);
            initParam.pNewUserPin = new Memory(NEW_PIN.length);
            initParam.pNewUserPin.write(0, NEW_PIN, 0, NEW_PIN.length);
            initParam.ulNewUserPinLen = new NativeLong(NEW_PIN.length);
            initParam.ulMinAdminPinLen = new NativeLong(6);
            initParam.ulMinUserPinLen = new NativeLong(6);
            initParam.ChangeUserPINPolicy = new NativeLong(
                    TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS_USER_CHANGE_USER_PIN);
            initParam.ulMaxAdminRetryCount = new NativeLong(MAX_ADMIN_RETRY_COUNT);
            initParam.ulMaxUserRetryCount = new NativeLong(MAX_USER_RETRY_COUNT);
            initParam.pTokenLabel = new Memory(TOKEN_LABEL.length());
            initParam.pTokenLabel.write(0, TOKEN_LABEL.getBytes(), 0, TOKEN_LABEL.length());
            initParam.ulLabelLen = new NativeLong(TOKEN_LABEL.length());
            initParam.ulSmMode = new NativeLong(0);
            initParam.ulSizeofThisStructure = new NativeLong(initParam.size());

            rv = pkcs11.C_EX_InitToken(token, DEFAULT_SO_PIN, new NativeLong(DEFAULT_SO_PIN.length), initParam);
            Pkcs11Exception.throwIfNotOk("C_EX_InitToken failed", rv);

            println("Opening session");
            NativeLongByReference sessionRef = new NativeLongByReference();
            rv = pkcs11.C_OpenSession(token, new NativeLong(CKF_SERIAL_SESSION | CKF_RW_SESSION),
                    null, null, sessionRef);
            Pkcs11Exception.throwIfNotOk("C_OpenSession failed", rv);
            session = sessionRef.getValue();

            println("Logging in as administrator");
            rv = pkcs11.C_Login(session, new NativeLong(CKU_SO), DEFAULT_SO_PIN, new NativeLong(DEFAULT_SO_PIN.length));
            Pkcs11Exception.throwIfNotOk("C_Login failed", rv);

            println("User PIN unlocking");
            rv = pkcs11.C_EX_UnblockUserPIN(session);
            Pkcs11Exception.throwIfNotOk("C_EX_UnblockUserPIN failed", rv);

            println("Logging out");
            rv = pkcs11.C_Logout(session);
            Pkcs11Exception.throwIfNotOk("C_Logout failed", rv);

            println("Logging in as user");
            rv = pkcs11.C_Login(session, new NativeLong(CKU_USER), NEW_PIN, new NativeLong(NEW_PIN.length));
            Pkcs11Exception.throwIfNotOk("C_Login failed", rv);

            println("Setting token name");
            rv = pkcs11.C_EX_SetTokenName(session, TOKEN_LONG_LABEL.getBytes(),
                    new NativeLong(TOKEN_LONG_LABEL.length()));
            Pkcs11Exception.throwIfNotOk("C_EX_SetTokenName failed", rv);

            println("User PIN changing");
            rv = pkcs11.C_SetPIN(session, NEW_PIN, new NativeLong(NEW_PIN.length), DEFAULT_USER_PIN,
                    new NativeLong(DEFAULT_USER_PIN.length));
            Pkcs11Exception.throwIfNotOk("C_SetPIN failed", rv);

            println("Sample has been completed successfully.");
        } catch (Exception e) {
            printlnError("Sample has failed:");
            e.printStackTrace();
        } finally {
            CommonPkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, session);
        }
    }
}

