package de.eround.v2g.authentication;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

public class Ocsp {
    public static Boolean validate(
            X509CertificateHolder leafCertificate,
            X509CertificateHolder rootCertificate,
            OCSPResp ocspResponse
    ) throws GeneralSecurityException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate x509LeafCertificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(leafCertificate.getEncoded())
        );
        X509Certificate x509RootCertificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(rootCertificate.getEncoded())
        );

        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(x509RootCertificate, null));

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(x509LeafCertificate);

        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, certSelector);

        CertStore certStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(Set.of(x509LeafCertificate)), BouncyCastleProvider.PROVIDER_NAME
        );
        pkixParams.addCertStore(certStore);

        // Disable revocation checking (we'll add our own revocation checker with the provided response)
        pkixParams.setRevocationEnabled(false);

        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) CertPathValidator.getInstance(
                "PKIX", BouncyCastleProvider.PROVIDER_NAME).getRevocationChecker();
        revocationChecker.setOptions(Set.of(PKIXRevocationChecker.Option.NO_FALLBACK));
        revocationChecker.setOcspResponses(Map.of(x509LeafCertificate, ocspResponse.getEncoded()));
        pkixParams.addCertPathChecker(revocationChecker);

        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
        certPathBuilder.build(pkixParams);
        return true;
    }
}
