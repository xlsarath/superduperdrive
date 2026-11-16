package io.github.xlsarath.superduperdrive.config;

import io.github.xlsarath.superduperdrive.crypto.keys.KeyBundleProtector;
import io.github.xlsarath.superduperdrive.crypto.sign.ManifestSigner;
import io.github.xlsarath.superduperdrive.crypto.suite.CryptoSuite;
import io.github.xlsarath.superduperdrive.crypto.suite.CryptoSuiteRegistry;
import io.github.xlsarath.superduperdrive.crypto.suite.HybridAesGcmSuiteV1;
import io.github.xlsarath.superduperdrive.crypto.suite.LegacyAesEcbCredentialSuite;
import io.github.xlsarath.superduperdrive.security.PasswordEncoders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

/** Wires the pure crypto layer into Spring. */
@Configuration(proxyBeanMethods = false)
public class CryptoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(CryptoConfiguration.class);

    /**
     * NIST SP 800-90A DRBG at 256-bit strength, seeded from the operating system and reseeded
     * automatically. Shared and thread-safe.
     */
    @Bean
    SecureRandom secureRandom() throws NoSuchAlgorithmException {
        SecureRandom drbg = SecureRandom.getInstance("DRBG", DrbgParameters.instantiation(256,
                DrbgParameters.Capability.RESEED_ONLY, "SuperDuperDrive".getBytes(StandardCharsets.US_ASCII)));
        log.info("SecureRandom initialised: {}", drbg);
        return drbg;
    }

    @Bean
    HybridAesGcmSuiteV1 hybridAesGcmSuiteV1(SecureRandom random, DriveProperties properties) {
        return new HybridAesGcmSuiteV1(random, properties.crypto().streamSegmentBytes());
    }

    @Bean
    LegacyAesEcbCredentialSuite legacyAesEcbCredentialSuite() {
        return new LegacyAesEcbCredentialSuite();
    }

    @Bean
    CryptoSuiteRegistry cryptoSuiteRegistry(List<CryptoSuite> suites, DriveProperties properties) {
        CryptoSuiteRegistry registry = new CryptoSuiteRegistry(suites, properties.crypto().currentSuite());
        log.info("Crypto suites registered: {}; current suite: {}",
                suites.stream().map(CryptoSuite::id).toList(), registry.current().id());
        return registry;
    }

    @Bean
    KeyBundleProtector keyBundleProtector(SecureRandom random, DriveProperties properties) {
        return new KeyBundleProtector(random, properties.crypto().keyWrap().toParams());
    }

    @Bean
    ManifestSigner manifestSigner(SecureRandom random) {
        return new ManifestSigner(random);
    }

    @Bean
    PasswordEncoder passwordEncoder(DriveProperties properties) {
        DriveProperties.Argon2 cost = properties.crypto().passwordHash();
        return PasswordEncoders.delegating(cost.memoryKib(), cost.iterations(), cost.parallelism());
    }
}
