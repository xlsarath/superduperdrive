package io.github.xlsarath.superduperdrive.config;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.ssl.SslBundleRegistrar;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;

/**
 * {@code pqtls} profile: serves HTTPS through Bouncy Castle JSSE with TLS 1.3 and the hybrid
 * {@code X25519MLKEM768} key-exchange group (draft-ietf-tls-ecdhe-mlkem), protecting traffic
 * against harvest-now-decrypt-later.
 *
 * <p>The certificate is a throw-away ECDSA P-256 certificate for {@code localhost}, generated in
 * memory at startup and never written to disk. Authentication stays classical on purpose:
 * browsers do not accept ML-DSA certificates yet, and authentication (unlike confidentiality)
 * cannot be broken retroactively.
 */
@Configuration(proxyBeanMethods = false)
@Profile("pqtls")
public class PqTlsConfiguration {

    public static final String BUNDLE = "pqtls";
    private static final Logger log = LoggerFactory.getLogger(PqTlsConfiguration.class);
    private static final String ALIAS = "superduperdrive-localhost";
    private static final String KEY_MANAGER_ALGORITHM_PROPERTY = "ssl.KeyManagerFactory.algorithm";

    /** The generated server certificate, exposed so tests can trust exactly this certificate. */
    public record PqTlsCertificate(X509Certificate certificate, KeyStore keyStore, String keyPassword) {
    }

    @Bean
    PqTlsCertificate pqTlsCertificate(SecureRandom random) throws GeneralSecurityException, IOException,
            OperatorCreationException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), random);
        KeyPair keyPair = generator.generateKeyPair();

        Instant now = Instant.now();
        X500Name subject = new X500Name("CN=localhost, O=SuperDuperDrive (development)");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, new BigInteger(127, random),
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(30))), subject,
                keyPair.getPublic())
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
                .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
                .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                        new GeneralName(GeneralName.dNSName, "localhost"),
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));

        byte[] passwordBytes = new byte[18];
        random.nextBytes(passwordBytes);
        String password = HexFormat.of().formatHex(passwordBytes);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(ALIAS, keyPair.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[] {certificate});
        log.info("Generated in-memory TLS certificate for localhost (ECDSA P-256, valid 30 days)");
        return new PqTlsCertificate(certificate, keyStore, password);
    }

    /**
     * Installs BCJSSE as the preferred JSSE provider (Tomcat obtains its {@code SSLContext} by
     * provider preference), selects BCJSSE's {@code PKIX} key manager (Tomcat builds its key
     * manager from the JDK default algorithm, and the JDK's {@code SunX509} manager cannot serve
     * BCJSSE's TLS 1.3 credential selection), restricts the key-exchange groups and registers the
     * SSL bundle.
     */
    @Bean
    SslBundleRegistrar pqTlsBundleRegistrar(PqTlsCertificate tls,
                                            @Value("${sdd.tls.named-groups:X25519MLKEM768,x25519,secp256r1}")
                                            String namedGroups) {
        installProviders();
        System.setProperty("jdk.tls.namedGroups", namedGroups);
        log.info("PQ-TLS enabled: BCJSSE provider, TLS 1.3, named groups {}", namedGroups);
        return registry -> registry.registerBundle(BUNDLE, SslBundle.of(
                SslStoreBundle.of(tls.keyStore(), tls.keyPassword(), null),
                SslBundleKey.of(tls.keyPassword(), ALIAS)));
    }

    private static synchronized void installProviders() {
        Provider bc = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (bc == null) {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleJsseProvider(bc), 1);
        }
        Security.setProperty(KEY_MANAGER_ALGORITHM_PROPERTY, "PKIX");
    }
}
