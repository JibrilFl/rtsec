/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.cmsoperations;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import static ru.rutoken.samples.utils.Util.getX509Certificate;

class CmsVerifier {
    private CmsVerifier() {
    }

    static boolean verifyCms(CMSSignedData cmsSignedData, List<X509CertificateHolder> trustedCerts,
                             List<X509CertificateHolder> intermediateCerts,
                             List<X509CertificateHolder> additionalCerts) {
        boolean result = false;
        try {
            HashSet<TrustAnchor> trustAnchors = new HashSet<>();
            for (X509CertificateHolder trustedCert : trustedCerts) {
                TrustAnchor trustAnchor = new TrustAnchor(getX509Certificate(trustedCert), null);
                trustAnchors.add(trustAnchor);
            }

            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX",
                    BouncyCastleProvider.PROVIDER_NAME);
            Store<X509CertificateHolder> cmsCertStore = cmsSignedData.getCertificates();
            Store<X509CertificateHolder> additionalCertsStore = new CollectionStore<>(additionalCerts);
            SignerInformationStore signers = cmsSignedData.getSignerInfos();

            for (SignerInformation signer : signers.getSigners()) {
                Collection<X509CertificateHolder> signerCertCollection = cmsCertStore.getMatches(signer.getSID());
                if (signerCertCollection.isEmpty()) {
                    Collection<X509CertificateHolder> signersFromUser =
                            additionalCertsStore.getMatches(signer.getSID());
                    if (signersFromUser.isEmpty())
                        throw new RuntimeException("No signer certificate found.");

                    signerCertCollection.addAll(signersFromUser);
                }

                for (X509CertificateHolder signerCert : signerCertCollection) {
                    // Validate signer's signature
                    if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerCert))) {
                        return false;
                    }

                    // Validate signer's certificate chain
                    X509CertSelector constraints = new X509CertSelector();
                    constraints.setCertificate(getX509Certificate(signerCert));
                    PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, constraints);

                    JcaCertStoreBuilder certStoreBuilder = new JcaCertStoreBuilder();
                    certStoreBuilder.addCertificate(signerCert);
                    for (X509CertificateHolder intermediateCert : intermediateCerts)
                        certStoreBuilder.addCertificate(intermediateCert);

                    params.addCertStore(certStoreBuilder.build());
                    // We disable revocation check for simplicity
                    // To enable it, you must also add CRLs in the CertStore above
                    params.setRevocationEnabled(false);
                    /* According to the Oracle's docs,
                     *      "all PKIX CertPathBuilders must return certification paths which have been
                     *      validated according to the PKIX certification path validation algorithm." */
                    certPathBuilder.build(params);
                    result = true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            result = false;
        }
        return result;
    }
}
