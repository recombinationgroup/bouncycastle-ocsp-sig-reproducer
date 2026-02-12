package de.eround.v2g.authentication;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

/**
 * Unit test for simple App.
 */
public class OcspTest {

    private KeyPair rootCaKeypair;
    private PublicKey rootCaPublicKey;
    private PrivateKey rootCaPrivateKey;
    private X509CertificateHolder rootCaCertificate;

    private KeyPair endEntityKeypair;
    private PublicKey endEntityPublicKey;
    private PrivateKey endEntityPrivateKey;
    private X509CertificateHolder endEntityCertificate;

    private KeyPair anotherKeypair;
    private PublicKey anotherPublicKey;
    private PrivateKey anotherPrivateKey;

    @Test
    void testWithValidOcsp() throws Exception {
        // Given a valid OCSP response signed by the root CA's private key indicating that the end entity certificate is good
        OCSPResp ocspResponse = generateOcspResponse(
                endEntityCertificate,
                rootCaCertificate,
                rootCaPrivateKey,
                CertificateStatus.GOOD
        );

        // When validating the end entity certificate with the supplied OCSP response
        Boolean isValid = Ocsp.validate(endEntityCertificate, rootCaCertificate, ocspResponse);

        // Then the validation should succeed
        assert(isValid);
    }

    @Test
    void testWithWrongKey() throws Exception {
        // Given an OCSP response signed with a different private key than the root CA's private key
        OCSPResp ocspResponse = generateOcspResponse(
                endEntityCertificate,
                rootCaCertificate,
                // Use another private key to sign the OCSP response, which should make it invalid
                //  due to the signature not matching the root CA's public key
                anotherPrivateKey,
                CertificateStatus.GOOD
        );

        // When validating the end entity certificate with the supplied OCSP response
        Boolean isValid = Ocsp.validate(endEntityCertificate, rootCaCertificate, ocspResponse);

        // Then the validation should fail because the OCSP response is not properly signed by the root CA
        assert(!isValid);
    }

    @BeforeEach
    public void beforeEach() throws Exception {
        // Generate Root CA key pair
        rootCaKeypair = generateKeyPair();
        rootCaPublicKey = rootCaKeypair.getPublic();
        rootCaPrivateKey = rootCaKeypair.getPrivate();

        // Generate End Entity key pair
        endEntityKeypair = generateKeyPair();
        endEntityPublicKey = endEntityKeypair.getPublic();
        endEntityPrivateKey = endEntityKeypair.getPrivate();

        // Generate another key pair
        anotherKeypair = generateKeyPair();
        anotherPublicKey = anotherKeypair.getPublic();
        anotherPrivateKey = anotherKeypair.getPrivate();

        // Generate Root CA certificate
        rootCaCertificate = generateCertificate(
                "Root CA",
                rootCaPublicKey,
                "Root CA",
                rootCaKeypair,
                true,
                null
        );

        // Generate End Entity certificate signed by Root CA
        endEntityCertificate = generateCertificate(
                "End Entity",
                endEntityPublicKey,
                "Root CA",
                rootCaKeypair,
                false,
                "http://ocsp.example.com"
        );
    }

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private X509CertificateHolder generateCertificate(String subject, PublicKey subjectPk, String issuerSubject, KeyPair issuerKeyPair, Boolean isCa, String ocspUrl) throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name("CN=" + issuerSubject),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24),
                new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365),
                new X500Name("CN=" + subject),
                SubjectPublicKeyInfo.getInstance(subjectPk.getEncoded())
        );

        builder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(isCa)
        );

        if (ocspUrl != null) {
            AccessDescription ad = new AccessDescription(
                    AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)
            );
            AuthorityInformationAccess aia = new AuthorityInformationAccess(ad);
            builder.addExtension(Extension.authorityInfoAccess, false, aia);
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(issuerKeyPair.getPrivate());

        return builder.build(contentSigner);
    }

    private OCSPResp generateOcspResponse(
            X509CertificateHolder leafCertificate,
            X509CertificateHolder rootCertificate,
            PrivateKey signerPrivateKey,
            CertificateStatus status
    ) throws OperatorCreationException, PEMException, OCSPException {
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
        BasicOCSPRespBuilder respBuilder = new JcaBasicOCSPRespBuilder(
                new JcaPEMKeyConverter().getPublicKey(rootCertificate.getSubjectPublicKeyInfo()), digestCalculator);


        CertificateID certId = new CertificateID(
                digestCalculator,
                rootCertificate,
                leafCertificate.getSerialNumber()
        );

        respBuilder.addResponse(certId, status);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(signerPrivateKey);

        X509CertificateHolder[] chain = new X509CertificateHolder[] { rootCertificate };
        BasicOCSPResp basicResp = respBuilder.build(contentSigner, chain, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);
    }
}
