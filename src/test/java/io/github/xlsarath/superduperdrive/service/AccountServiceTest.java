package io.github.xlsarath.superduperdrive.service;

import io.github.xlsarath.superduperdrive.domain.UserAccount;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import io.github.xlsarath.superduperdrive.service.account.AccountService;
import io.github.xlsarath.superduperdrive.service.account.KeyUnlockException;
import io.github.xlsarath.superduperdrive.service.account.RecoveryFailedException;
import io.github.xlsarath.superduperdrive.service.account.SignupCommand;
import io.github.xlsarath.superduperdrive.service.account.UnlockResult;
import io.github.xlsarath.superduperdrive.service.account.UsernameTakenException;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import io.github.xlsarath.superduperdrive.support.TestUsers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class AccountServiceTest {

    @Autowired
    AccountService accounts;
    @Autowired
    UserAccountRepository users;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    TestUsers testUsers;

    @Test
    void registrationStoresHashPublicKeysAndTwoWrappedBundles() {
        String username = TestUsers.uniqueUsername();
        String recoveryKey = testUsers.register(username);

        UserAccount account = users.findByUsername(username).orElseThrow();
        assertThat(recoveryKey).matches("([A-Z2-7]{4}-){13}[A-Z2-7]{4}");
        assertThat(account.getPasswordHash()).startsWith("{argon2}$argon2id$");
        assertThat(account.hasKeys()).isTrue();
        assertThat(account.getKeySuite()).isEqualTo(UserAccount.KEY_SUITE);
        assertThat(account.publicKeys()).isPresent();
        assertThat(account.passwordWrappedKeys()).isPresent();
        assertThat(account.recoveryWrappedKeys()).isPresent();
    }

    @Test
    void usernamesAreCaseInsensitiveAndUnique() {
        String username = TestUsers.uniqueUsername();
        testUsers.register(username);
        assertThatThrownBy(() -> accounts.register(new SignupCommand("Ada", "Lovelace",
                username.toUpperCase(Locale.ROOT), "another-password-1".toCharArray())))
                .isInstanceOf(UsernameTakenException.class);
    }

    @Test
    void unlockYieldsKeysMatchingTheStoredPublicKeys() {
        ActiveUser user = testUsers.signedIn();
        UserAccount account = users.findById(user.id()).orElseThrow();
        assertThat(user.keyring().publicKeys()).isEqualTo(account.publicKeys().orElseThrow());
        user.keyring().close();
        assertThat(user.keyring().isClosed()).isTrue();
        assertThatThrownBy(() -> user.keyring().hybridPrivateKey()).isInstanceOf(KeysLockedException.class);
    }

    @Test
    void unlockRefusesAKeyBundleWhosePublicKeysWereSwapped() {
        String victim = TestUsers.uniqueUsername();
        String attacker = TestUsers.uniqueUsername();
        testUsers.register(victim);
        testUsers.register(attacker);
        UserAccount victimAccount = users.findByUsername(victim).orElseThrow();
        UserAccount attackerAccount = users.findByUsername(attacker).orElseThrow();

        // A database-level attacker replaces the victim's public keys with their own.
        victimAccount.installKeys(attackerAccount.publicKeys().orElseThrow(),
                victimAccount.passwordWrappedKeys().orElseThrow(), victimAccount.recoveryWrappedKeys().orElseThrow(),
                java.time.Instant.now());
        users.saveAndFlush(victimAccount);

        assertThatThrownBy(() -> accounts.unlock(victimAccount.getId(), TestUsers.PASSWORD.toCharArray()))
                .isInstanceOf(KeyUnlockException.class);
    }

    @Test
    void recoveryResetsThePasswordAndRotatesTheRecoveryKey() {
        String username = TestUsers.uniqueUsername();
        String recoveryKey = testUsers.register(username);
        UserAccount before = users.findByUsername(username).orElseThrow();

        String newRecoveryKey = accounts.recover(username, recoveryKey.toLowerCase(Locale.ROOT),
                "a-brand-new-passphrase".toCharArray());

        UserAccount after = users.findByUsername(username).orElseThrow();
        assertThat(newRecoveryKey).isNotEqualTo(recoveryKey);
        assertThat(passwordEncoder.matches("a-brand-new-passphrase", after.getPasswordHash())).isTrue();
        assertThat(passwordEncoder.matches(TestUsers.PASSWORD, after.getPasswordHash())).isFalse();
        UnlockResult unlocked = accounts.unlock(after.getId(), "a-brand-new-passphrase".toCharArray());
        assertThat(unlocked.keyring().publicKeys()).isEqualTo(before.publicKeys().orElseThrow());

        // The old recovery key is retired.
        assertThatThrownBy(() -> accounts.recover(username, recoveryKey, "yet-another-passphrase".toCharArray()))
                .isInstanceOf(RecoveryFailedException.class);
        assertThat(accounts.recover(username, newRecoveryKey, "yet-another-passphrase".toCharArray())).isNotBlank();
    }

    @Test
    void recoveryFailuresAreIndistinguishableAndWrongKeysCountTowardsLockout() {
        String username = TestUsers.uniqueUsername();
        testUsers.register(username);
        String wrongKey;
        try (var other = io.github.xlsarath.superduperdrive.crypto.keys.RecoveryKey.generate(TestKeys.RANDOM)) {
            wrongKey = other.display();
        }
        assertThatThrownBy(() -> accounts.recover("nobody-here", wrongKey, "x-x-x-x-x-x-x".toCharArray()))
                .isInstanceOf(RecoveryFailedException.class);
        assertThatThrownBy(() -> accounts.recover(username, "garbage", "x-x-x-x-x-x-x".toCharArray()))
                .isInstanceOf(RecoveryFailedException.class);
        for (int i = 0; i < 5; i++) {
            assertThatThrownBy(() -> accounts.recover(username, wrongKey, "x-x-x-x-x-x-x".toCharArray()))
                    .isInstanceOf(RecoveryFailedException.class);
        }
        assertThat(users.findByUsername(username).orElseThrow().isLockedAt(java.time.Instant.now())).isTrue();
    }
}
