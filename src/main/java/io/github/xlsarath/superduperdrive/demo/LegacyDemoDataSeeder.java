package io.github.xlsarath.superduperdrive.demo;

import io.github.xlsarath.superduperdrive.crypto.suite.LegacyAesEcbCredentialSuite;
import io.github.xlsarath.superduperdrive.domain.Credential;
import io.github.xlsarath.superduperdrive.domain.UserAccount;
import io.github.xlsarath.superduperdrive.repository.CredentialRepository;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * {@code demo} profile only: inserts one account exactly as the 2020 application stored it,
 * so the login-time migration (PBKDF2 to Argon2id, key provisioning, AES-ECB to the hybrid
 * suite) can be watched end to end. Values below are fake demo data, produced with the 2020
 * algorithms: user {@code grace}, password {@code grace-hopper-1906}.
 */
@Component
@Profile("demo")
@ConditionalOnProperty(name = "sdd.demo.legacy-account", havingValue = "true")
public class LegacyDemoDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(LegacyDemoDataSeeder.class);
    static final String USERNAME = "grace";
    private static final String LEGACY_HASH =
            "{legacy-pbkdf2-sha1}3JtJsoXJ9Q94vScIO8l2Gw==$0f0aJ9fyQzEQU4ORvcxztg==";

    private final UserAccountRepository users;
    private final CredentialRepository credentials;

    public LegacyDemoDataSeeder(UserAccountRepository users, CredentialRepository credentials) {
        this.users = users;
        this.credentials = credentials;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (users.existsByUsername(USERNAME)) {
            return;
        }
        UUID id = UUID.randomUUID();
        users.save(new UserAccount(id, USERNAME, LEGACY_HASH, "Grace", "Hopper"));
        credentials.save(Credential.legacy(UUID.randomUUID(), id, LegacyAesEcbCredentialSuite.ID,
                "https://example.org", "grace", "kh1dzoGmM40lvT8+GnvE8Q==",
                "HUQHSPSbVLk92JyMNQgCF/7zIYsyJpm8erP3jnK2P9E="));
        credentials.save(Credential.legacy(UUID.randomUUID(), id, LegacyAesEcbCredentialSuite.ID,
                "https://example.net", "rear-admiral", "4Xr67JEHgWzx1ZZpddc5ww==",
                "1iLiBM5nRogZdkCyIICFbgfDI7hO+KwvBrXgxnYC4C0="));
        log.info("Seeded legacy demo account {} with 2 AES-ECB credentials awaiting migration", id);
    }
}
