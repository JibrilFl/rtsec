/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.utils;

import com.sun.jna.Memory;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import ru.rutoken.pkcs11jna.CK_DATE;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Locale;
import java.util.Random;

import static org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
import static org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
import static org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
import static org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation;
import static ru.rutoken.samples.utils.CommonUtil.println;

public final class Util {
    public static final byte[] RECIPIENT_GOST_PUBLIC_KEY_256 = {
            (byte) 0x76, (byte) 0x25, (byte) 0x13, (byte) 0x0F, (byte) 0x19, (byte) 0x17, (byte) 0x3D, (byte) 0x3B,
            (byte) 0x24, (byte) 0xCC, (byte) 0xA7, (byte) 0xC7, (byte) 0x72, (byte) 0xB3, (byte) 0x5D, (byte) 0x83,
            (byte) 0xB0, (byte) 0xBB, (byte) 0x42, (byte) 0xC9, (byte) 0x66, (byte) 0xD5, (byte) 0xC1, (byte) 0x5A,
            (byte) 0x0A, (byte) 0x9F, (byte) 0xD4, (byte) 0x24, (byte) 0xF0, (byte) 0x46, (byte) 0xB2, (byte) 0xCD,
            (byte) 0x85, (byte) 0xDD, (byte) 0xC5, (byte) 0x73, (byte) 0xAE, (byte) 0x72, (byte) 0x8D, (byte) 0x6F,
            (byte) 0xC8, (byte) 0x9C, (byte) 0xE2, (byte) 0x5B, (byte) 0x89, (byte) 0x05, (byte) 0xE8, (byte) 0x9D,
            (byte) 0x75, (byte) 0x93, (byte) 0xBF, (byte) 0xE9, (byte) 0x38, (byte) 0xC3, (byte) 0x43, (byte) 0x27,
            (byte) 0x09, (byte) 0x59, (byte) 0x7E, (byte) 0x7D, (byte) 0x51, (byte) 0xA8, (byte) 0x35, (byte) 0x53
    };

    public static final byte[] RECIPIENT_GOST_PUBLIC_KEY_512 = {
            (byte) 0xFC, (byte) 0xD5, (byte) 0xD3, (byte) 0x91, (byte) 0xEF, (byte) 0x58, (byte) 0x66, (byte) 0x50,
            (byte) 0x26, (byte) 0x59, (byte) 0x6C, (byte) 0x71, (byte) 0xE5, (byte) 0x89, (byte) 0x35, (byte) 0xC7,
            (byte) 0x35, (byte) 0x71, (byte) 0x28, (byte) 0xA4, (byte) 0xAD, (byte) 0x3C, (byte) 0xD5, (byte) 0x0A,
            (byte) 0xA3, (byte) 0xF8, (byte) 0xB1, (byte) 0xD9, (byte) 0xC1, (byte) 0x77, (byte) 0xB3, (byte) 0x17,
            (byte) 0x65, (byte) 0x0C, (byte) 0x7E, (byte) 0x6E, (byte) 0x11, (byte) 0x12, (byte) 0xC2, (byte) 0x62,
            (byte) 0xB3, (byte) 0xDF, (byte) 0x43, (byte) 0x32, (byte) 0x54, (byte) 0xB4, (byte) 0x7C, (byte) 0x7D,
            (byte) 0xF3, (byte) 0x3C, (byte) 0x1F, (byte) 0xD7, (byte) 0xEA, (byte) 0x02, (byte) 0xE7, (byte) 0x70,
            (byte) 0x15, (byte) 0xCC, (byte) 0xFC, (byte) 0x28, (byte) 0xC6, (byte) 0xAE, (byte) 0x91, (byte) 0x29,
            (byte) 0x58, (byte) 0xFB, (byte) 0x75, (byte) 0x14, (byte) 0x7B, (byte) 0x0E, (byte) 0x99, (byte) 0x59,
            (byte) 0xF9, (byte) 0x4B, (byte) 0xE9, (byte) 0x80, (byte) 0xA5, (byte) 0xBB, (byte) 0x18, (byte) 0x8E,
            (byte) 0xED, (byte) 0x43, (byte) 0xCC, (byte) 0x8D, (byte) 0x9E, (byte) 0x39, (byte) 0x14, (byte) 0x6A,
            (byte) 0xBA, (byte) 0xC7, (byte) 0x5F, (byte) 0xFF, (byte) 0x02, (byte) 0x4C, (byte) 0x1C, (byte) 0x9E,
            (byte) 0xFE, (byte) 0x71, (byte) 0xF2, (byte) 0xC3, (byte) 0xFD, (byte) 0xD6, (byte) 0x1C, (byte) 0x76,
            (byte) 0xBE, (byte) 0xCF, (byte) 0x77, (byte) 0xB6, (byte) 0xD7, (byte) 0x5D, (byte) 0xFF, (byte) 0x35,
            (byte) 0x3C, (byte) 0x35, (byte) 0x70, (byte) 0x78, (byte) 0x03, (byte) 0xED, (byte) 0x6E, (byte) 0x0A,
            (byte) 0x03, (byte) 0x65, (byte) 0xDC, (byte) 0xA4, (byte) 0xAA, (byte) 0x59, (byte) 0x8B, (byte) 0xDB
    };

    public static final byte[] RECIPIENT_ECDSA_SECP256K1_PUBLIC_KEY = {
            (byte) 0x04, (byte) 0x41, (byte) 0x04, (byte) 0x7D, (byte) 0xF4, (byte) 0x6F, (byte) 0x45, (byte) 0x38,
            (byte) 0x2D, (byte) 0xC6, (byte) 0x86, (byte) 0xD3, (byte) 0xBB, (byte) 0x3E, (byte) 0xF8, (byte) 0x73,
            (byte) 0xD4, (byte) 0x1B, (byte) 0x4C, (byte) 0xD6, (byte) 0x06, (byte) 0xA3, (byte) 0x7D, (byte) 0x0B,
            (byte) 0xFA, (byte) 0xDE, (byte) 0x4D, (byte) 0x15, (byte) 0x66, (byte) 0xAB, (byte) 0x04, (byte) 0x6F,
            (byte) 0x19, (byte) 0x3F, (byte) 0x26, (byte) 0xA1, (byte) 0x6A, (byte) 0x5A, (byte) 0x20, (byte) 0x97,
            (byte) 0x9F, (byte) 0x63, (byte) 0xFF, (byte) 0xB4, (byte) 0x27, (byte) 0x2B, (byte) 0x9F, (byte) 0x49,
            (byte) 0x0D, (byte) 0x2F, (byte) 0xD2, (byte) 0xE1, (byte) 0x45, (byte) 0x9E, (byte) 0x8E, (byte) 0xBC,
            (byte) 0xE0, (byte) 0x72, (byte) 0xBA, (byte) 0x23, (byte) 0x73, (byte) 0x43, (byte) 0x4E, (byte) 0xCD,
            (byte) 0x00, (byte) 0x9F, (byte) 0x8B
    };

    public static final byte[] RECIPIENT_ECDSA_SECP256R1_PUBLIC_KEY = {
            (byte) 0x04, (byte) 0x41, (byte) 0x04, (byte) 0x97, (byte) 0xB2, (byte) 0x8C, (byte) 0xB4, (byte) 0x93,
            (byte) 0x1C, (byte) 0xA1, (byte) 0x7F, (byte) 0xD0, (byte) 0x57, (byte) 0xA0, (byte) 0x58, (byte) 0x2B,
            (byte) 0xF7, (byte) 0x10, (byte) 0xE8, (byte) 0x41, (byte) 0x98, (byte) 0xFC, (byte) 0x4B, (byte) 0x59,
            (byte) 0x78, (byte) 0x07, (byte) 0x33, (byte) 0x1E, (byte) 0x70, (byte) 0x5F, (byte) 0x61, (byte) 0x39,
            (byte) 0xAB, (byte) 0x3A, (byte) 0xD4, (byte) 0xC4, (byte) 0x45, (byte) 0x07, (byte) 0x5D, (byte) 0xC6,
            (byte) 0x0D, (byte) 0x1D, (byte) 0xA3, (byte) 0xA7, (byte) 0x52, (byte) 0xF2, (byte) 0xD7, (byte) 0xFA,
            (byte) 0xD1, (byte) 0xEE, (byte) 0x4B, (byte) 0xCE, (byte) 0xD1, (byte) 0xEA, (byte) 0x58, (byte) 0x30,
            (byte) 0xF6, (byte) 0x9F, (byte) 0x0D, (byte) 0x9D, (byte) 0x63, (byte) 0x6C, (byte) 0xAF, (byte) 0x89,
            (byte) 0x7E, (byte) 0xB9, (byte) 0xD5
    };

    public static final byte[] RECIPIENT_ECDSA_SECP384R1_PUBLIC_KEY = {
            (byte) 0x04, (byte) 0x61, (byte) 0x04, (byte) 0xAC, (byte) 0x7F, (byte) 0x9A, (byte) 0x58, (byte) 0x8B,
            (byte) 0x76, (byte) 0xF1, (byte) 0x17, (byte) 0x3E, (byte) 0xC6, (byte) 0xB4, (byte) 0xE2, (byte) 0x27,
            (byte) 0x9C, (byte) 0x1D, (byte) 0x22, (byte) 0xE4, (byte) 0x12, (byte) 0x0A, (byte) 0x3C, (byte) 0x66,
            (byte) 0x21, (byte) 0x99, (byte) 0x6B, (byte) 0x59, (byte) 0xD9, (byte) 0x15, (byte) 0x12, (byte) 0x31,
            (byte) 0xAB, (byte) 0x0A, (byte) 0x80, (byte) 0x85, (byte) 0x1B, (byte) 0xA3, (byte) 0x19, (byte) 0xDF,
            (byte) 0x42, (byte) 0x07, (byte) 0x8E, (byte) 0x6F, (byte) 0xEA, (byte) 0x68, (byte) 0xB5, (byte) 0x45,
            (byte) 0xC8, (byte) 0x36, (byte) 0x74, (byte) 0x03, (byte) 0x0B, (byte) 0x57, (byte) 0xEB, (byte) 0xE6,
            (byte) 0x1C, (byte) 0xD0, (byte) 0x39, (byte) 0x9C, (byte) 0xD3, (byte) 0x81, (byte) 0x45, (byte) 0x83,
            (byte) 0x49, (byte) 0x25, (byte) 0x2E, (byte) 0x4E, (byte) 0x00, (byte) 0x08, (byte) 0xC3, (byte) 0x80,
            (byte) 0x29, (byte) 0x6D, (byte) 0x0F, (byte) 0x2B, (byte) 0x79, (byte) 0x2A, (byte) 0xBB, (byte) 0x2F,
            (byte) 0x8A, (byte) 0x5D, (byte) 0xDB, (byte) 0x86, (byte) 0x57, (byte) 0x60, (byte) 0x79, (byte) 0x14,
            (byte) 0x81, (byte) 0x61, (byte) 0x55, (byte) 0xA6, (byte) 0x67, (byte) 0x08, (byte) 0xFD, (byte) 0xB3,
            (byte) 0x17, (byte) 0x1C, (byte) 0x64
    };

    public static final byte[] RECIPIENT_ECDSA_SECP521R1_PUBLIC_KEY = {
            (byte) 0x04, (byte) 0x81, (byte) 0x85, (byte) 0x04, (byte) 0x01, (byte) 0x1E, (byte) 0x38, (byte) 0xD7,
            (byte) 0x74, (byte) 0xCD, (byte) 0x9B, (byte) 0x1F, (byte) 0xDD, (byte) 0xC7, (byte) 0x52, (byte) 0x3F,
            (byte) 0xD2, (byte) 0xF1, (byte) 0x87, (byte) 0xDD, (byte) 0xDB, (byte) 0x3A, (byte) 0xFA, (byte) 0x13,
            (byte) 0xE2, (byte) 0xF4, (byte) 0xCC, (byte) 0xF1, (byte) 0x50, (byte) 0x97, (byte) 0x06, (byte) 0x1C,
            (byte) 0x2B, (byte) 0xE5, (byte) 0xA4, (byte) 0x57, (byte) 0xAA, (byte) 0x6E, (byte) 0xBF, (byte) 0x5C,
            (byte) 0x8F, (byte) 0x63, (byte) 0x2C, (byte) 0x2C, (byte) 0xAE, (byte) 0x91, (byte) 0x26, (byte) 0xB1,
            (byte) 0x9E, (byte) 0xB2, (byte) 0xA8, (byte) 0xA1, (byte) 0xEE, (byte) 0x85, (byte) 0x01, (byte) 0xDE,
            (byte) 0x81, (byte) 0x8E, (byte) 0xFE, (byte) 0xA9, (byte) 0x5E, (byte) 0x2D, (byte) 0x93, (byte) 0xBD,
            (byte) 0x51, (byte) 0x0A, (byte) 0x6D, (byte) 0x09, (byte) 0xE2, (byte) 0xBB, (byte) 0x01, (byte) 0xF8,
            (byte) 0x81, (byte) 0x5D, (byte) 0x9B, (byte) 0x0D, (byte) 0x43, (byte) 0x67, (byte) 0x7C, (byte) 0x79,
            (byte) 0xB9, (byte) 0x57, (byte) 0x75, (byte) 0x1D, (byte) 0x8C, (byte) 0x94, (byte) 0x4B, (byte) 0xD7,
            (byte) 0x5B, (byte) 0xDC, (byte) 0x35, (byte) 0xCC, (byte) 0x01, (byte) 0x31, (byte) 0xDB, (byte) 0xBB,
            (byte) 0x7A, (byte) 0xD7, (byte) 0x80, (byte) 0xCC, (byte) 0x24, (byte) 0x20, (byte) 0x6E, (byte) 0xB5,
            (byte) 0x54, (byte) 0xC5, (byte) 0xE4, (byte) 0xD8, (byte) 0x65, (byte) 0x08, (byte) 0x05, (byte) 0x6C,
            (byte) 0xCF, (byte) 0x06, (byte) 0x5A, (byte) 0xC1, (byte) 0xDD, (byte) 0xC8, (byte) 0x54, (byte) 0x26,
            (byte) 0x72, (byte) 0x5C, (byte) 0xEF, (byte) 0x5A, (byte) 0x77, (byte) 0x1B, (byte) 0x3C, (byte) 0xC1,
            (byte) 0xBE, (byte) 0xF0, (byte) 0xA9, (byte) 0x43, (byte) 0x26, (byte) 0xC7, (byte) 0x8A, (byte) 0xC7
    };

    /**
     * List of DN (Distinguished Name) fields for PKCS#11 functions
     */
    public final static String[] PKCS11_DN = {
            "CN",
            "Иванов",
            "C",
            "RU",
            "2.5.4.5",
            "12312312312",
            "1.2.840.113549.1.9.1",
            "ivanov@mail.ru",
            "ST",
            "Moscow",
    };

    /**
     * List of DN (Distinguished Name) fields for Bouncy Castle methods
     */
    public final static RDN[] BC_DN = {
            new RDN(BCStyle.CN, new DERUTF8String("Ivanoff")),
            new RDN(BCStyle.C, new DERPrintableString("RU")),
            new RDN(BCStyle.SERIALNUMBER, new DERPrintableString("12312312312")),
            new RDN(BCStyle.EmailAddress, new DERIA5String("ivanov@mail.ru")),
            new RDN(BCStyle.ST, new DERUTF8String("Moscow")),
    };

    /**
     * List of extension fields for PKCS#11 functions
     */
    public final static String[] PKCS11_EXTS = {
            "keyUsage",
            // Marked as critical in accordance with RFC 5280, section 4.2.1.3
            "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment",
            "extendedKeyUsage",
            "1.2.643.2.2.34.6,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4",
    };

    /**
     * List of extension fields for Bouncy Castle methods
     */
    public final static Extensions BC_EXTS = createBcExtensions();

    private Util() {
    }

    public static void printCsr(String label, byte[] csrDer) {
        println(label);

        final int lineWidth = 64;
        // Encode from der to base64
        String csrBase64 = Base64.getEncoder().encodeToString(csrDer);
        int k = 0;
        while (k < csrBase64.length() / lineWidth) {
            println(csrBase64.substring(k * lineWidth, (k + 1) * lineWidth));
            k++;
        }
        println(csrBase64.substring(k * lineWidth));
        System.out.println();
    }

    public static Memory allocateDeriveParamsGOSTR3410_2012(int kdf, byte[] key, byte[] ukm) {
        ByteBuffer s = ByteBuffer.allocate(3 * Integer.BYTES + key.length * Byte.BYTES + ukm.length * Byte.BYTES);
        s.order(ByteOrder.LITTLE_ENDIAN);
        s.putInt(kdf);
        s.putInt(key.length);
        s.put(key);
        s.putInt(ukm.length);
        s.put(ukm);

        Memory p = new Memory(s.capacity());
        p.write(0, s.array(), 0, s.capacity());

        return p;
    }

    public static String cmsToPem(byte[] encodedCms) throws IOException {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(ContentInfo.getInstance(encodedCms));
            pemWriter.flush();
            return stringWriter.toString();
        }
    }

    public static String certificateToPem(byte[] encodedCertificate) throws IOException {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(new X509CertificateHolder(encodedCertificate));
            pemWriter.flush();
            return stringWriter.toString();
        }
    }

    public static String getCertificateInfo(byte[] certificateValue) throws IOException {
        X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateValue);
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy HH:mm");
        return certificateHolder.getSubject().toString() +
                " from " + dateFormat.format(certificateHolder.getNotBefore()) +
                " to " + dateFormat.format(certificateHolder.getNotAfter());
    }

    public static X509CertificateHolder getX509CertificateHolder(String fileName)
            throws IOException, CertificateException {
        InputStream in = new FileInputStream(fileName);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
        return new X509CertificateHolder(cert.getEncoded());
    }

    public static X509Certificate getX509Certificate(X509CertificateHolder certificateHolder)
            throws CertificateException {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateHolder);
    }

    public static X509Certificate getX509Certificate(byte[] certificateValue) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificateValue));
    }

    public static CMSSignedData readCmsFromFile(String filename) throws IOException, CMSException {
        File f = new File(filename);
        try (PemReader reader = new PemReader(new FileReader(f))) {
            PemObject pemObject = reader.readPemObject();
            return new CMSSignedData(pemObject.getContent());
        }
    }

    public static CMSSignedData getCmsFromBytes(byte[] encodedCms) throws IOException, CMSException {
        ContentInfo contentInfo = ContentInfo.getInstance(ASN1Sequence.fromByteArray(encodedCms));
        return new CMSSignedData(contentInfo);
    }

    public static <T> T TODO(String reason) {
        throw new UnsupportedOperationException(reason);
    }

    public static byte[] generateRandom(int size) {
        Random r = new Random();
        byte[] randomBytes = new byte[size];
        r.nextBytes(randomBytes);
        return randomBytes;
    }

    public static CK_DATE toCkDate(ZonedDateTime zonedDateTime) {
        byte[] year = String.format(Locale.US, "%04d", zonedDateTime.getYear()).getBytes();
        byte[] month = String.format(Locale.US, "%02d", zonedDateTime.getMonthValue()).getBytes();
        byte[] day = String.format(Locale.US, "%02d", zonedDateTime.getDayOfMonth()).getBytes();
        CK_DATE ckDate = new CK_DATE(year, month, day);
        ckDate.write();
        return ckDate;
    }

    private static Extensions createBcExtensions() {
        try {
            KeyUsage keyUsage = new KeyUsage(digitalSignature | nonRepudiation | keyEncipherment | dataEncipherment);

            ASN1EncodableVector encodableVector = new ASN1EncodableVector();
            encodableVector.add(new ASN1ObjectIdentifier("1.2.643.2.2.34.6"));
            encodableVector.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2"));
            encodableVector.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4"));
            ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(new DERSequence(encodableVector));

            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            // Marked as critical in accordance with RFC 5280, section 4.2.1.3
            extensionsGenerator.addExtension(Extension.keyUsage, true, keyUsage);
            extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
            return extensionsGenerator.generate();
        } catch (Exception ignored) {
        }

        return null; // Ignored because the exception is never thrown
    }
}
