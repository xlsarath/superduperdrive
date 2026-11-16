package io.github.xlsarath.superduperdrive.service.account;

import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import io.github.xlsarath.superduperdrive.crypto.keys.KeyBundleProtector;
import io.github.xlsarath.superduperdrive.crypto.keys.RecoveryKey;
import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;
import io.github.xlsarath.superduperdrive.crypto.keys.UserPublicKeys;
import io.github.xlsarath.superduperdrive.crypto.keys.WrappedKeyBundle;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import io.github.xlsarath.superduperdrive.domain.UserAccount;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import io.github.xlsarath.superduperdrive.service.UnlockedKeyring;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/**
 * Account lifecycle: registration with key generation, unlocking keys at login, and recovery
 * with the user-held recovery key.
 */
@Service
public class AccountService {

    private static final Logger log = LoggerFactory.getLogger(AccountService.class);

    private final UserAccountRepository users;
    private final PasswordEncoder passwordEncoder;
    private final KeyBundleProtector protector;
    private final LoginAttemptService loginAttempts;
    private final SecureRandom random;
    private final Clock clock;

    public AccountService(UserAccountRepository users, PasswordEncoder passwordEncoder, KeyBundleProtector protector,
                          LoginAttemptService loginAttempts, SecureRandom random, Clock clock) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.protector = protector;
        this.loginAttempts = loginAttempts;
        this.random = random;
        this.clock = clock;
    }

    public static String normalizeUsername(String username) {
        return username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
    }

    /**
     * Creates the account and its key pairs.
     *
     * @return the recovery key, formatted for display; it is not stored anywhere in plaintext
     * @throws UsernameTakenException if the username exists (also under a concurrent signup)
     */
    @Transactional
    public String register(SignupCommand command) {
        String username = normalizeUsername(command.username());
        char[] password = command.password();
        try {
            if (users.existsByUsername(username)) {
                throw new UsernameTakenException();
            }
            UUID id = UUID.randomUUID();
            UserAccount account = new UserAccount(id, username, passwordEncoder.encode(String.valueOf(password)),
                    command.firstName().strip(), command.lastName().strip());
            String recoveryKey;
            try (UserKeyMaterial keys = UserKeyMaterial.generate(random)) {
                recoveryKey = installNewKeys(account, password, keys);
            }
            users.saveAndFlush(account);
            log.info("Registered user {} with key suite {}", id, UserAccount.KEY_SUITE);
            return recoveryKey;
        } catch (DataIntegrityViolationException e) {
            log.info("Signup lost a race for an existing username");
            throw new UsernameTakenException();
        } finally {
            Bytes.wipe(password);
        }
    }

    /**
     * Unlocks the user's keys with the password that has just been verified by Spring Security.
     * Accounts from the 2020 schema have no keys yet: they are generated now and a recovery key
     * is issued.
     */
    @Transactional
    public UnlockResult unlock(UUID userId, char[] password) {
        UserAccount account = users.findById(userId)
                .orElseThrow(() -> new KeyUnlockException("account disappeared during login", null));
        if (!account.hasKeys()) {
            UserKeyMaterial keys = UserKeyMaterial.generate(random);
            String recoveryKey = installNewKeys(account, password, keys);
            users.save(account);
            log.info("Provisioned keys for pre-existing user {} at first login", userId);
            return new UnlockResult(new UnlockedKeyring(userId, keys), Optional.of(recoveryKey));
        }
        WrappedKeyBundle bundle = account.passwordWrappedKeys().orElseThrow();
        UserKeyMaterial keys;
        try {
            keys = protector.unwrapWithPassword(userId, password, bundle);
        } catch (IntegrityException e) {
            log.error("Key bundle of user {} did not open although the password hash matched", userId);
            throw new KeyUnlockException("key bundle failed to authenticate", e);
        }
        requireMatchingPublicKeys(account, keys);
        log.debug("Unlocked keys of user {} ({})", userId, bundle);
        return new UnlockResult(new UnlockedKeyring(userId, keys), Optional.empty());
    }

    /**
     * Resets the password using the recovery key, re-wraps the private keys under the new
     * password and issues a fresh recovery key (the old one stops working).
     *
     * @return the new recovery key for display
     * @throws RecoveryFailedException for any failure, without saying which
     */
    @Transactional(noRollbackFor = RecoveryFailedException.class)
    public String recover(String usernameInput, String recoveryKeyInput, char[] newPassword) {
        String username = normalizeUsername(usernameInput);
        try (RecoveryKey presented = parseOrFail(recoveryKeyInput)) {
            UserAccount account = users.findByUsername(username).orElseThrow(() -> {
                log.info("Recovery attempt for an unknown username");
                return new RecoveryFailedException();
            });
            if (account.isLockedAt(clock.instant()) || account.recoveryWrappedKeys().isEmpty()) {
                log.warn("Recovery refused for user {}: locked or no recovery bundle", account.getId());
                throw new RecoveryFailedException();
            }
            UserKeyMaterial keys;
            try {
                keys = protector.unwrapWithRecoveryKey(account.getId(), presented, account.recoveryWrappedKeys().get());
            } catch (IntegrityException e) {
                loginAttempts.recordFailure(username);
                log.warn("Recovery key rejected for user {}", account.getId());
                throw new RecoveryFailedException();
            }
            try (keys) {
                requireMatchingPublicKeys(account, keys);
                account.changePasswordHash(passwordEncoder.encode(String.valueOf(newPassword)));
                account.replacePasswordWrappedKeys(protector.wrapWithPassword(account.getId(), newPassword, keys));
                String newRecoveryKey;
                try (RecoveryKey fresh = RecoveryKey.generate(random)) {
                    account.replaceRecoveryWrappedKeys(protector.wrapWithRecoveryKey(account.getId(), fresh, keys),
                            clock.instant());
                    newRecoveryKey = fresh.display();
                }
                account.clearFailedLogins();
                users.save(account);
                log.info("User {} recovered their account; password reset and recovery key rotated", account.getId());
                return newRecoveryKey;
            }
        } finally {
            Bytes.wipe(newPassword);
        }
    }

    private RecoveryKey parseOrFail(String input) {
        try {
            return RecoveryKey.parse(input);
        } catch (RecoveryKey.InvalidRecoveryKeyException e) {
            // Typos are caught by the checksum and do not count as a failed attempt.
            log.info("Malformed recovery key submitted");
            throw new RecoveryFailedException();
        }
    }

    private String installNewKeys(UserAccount account, char[] password, UserKeyMaterial keys) {
        try (RecoveryKey recoveryKey = RecoveryKey.generate(random)) {
            Instant now = clock.instant();
            UserPublicKeys publicKeys = keys.publicKeys();
            account.installKeys(publicKeys,
                    protector.wrapWithPassword(account.getId(), password, keys),
                    protector.wrapWithRecoveryKey(account.getId(), recoveryKey, keys),
                    now);
            return recoveryKey.display();
        }
    }

    private static void requireMatchingPublicKeys(UserAccount account, UserKeyMaterial keys) {
        UserPublicKeys derived = keys.publicKeys();
        if (!account.publicKeys().map(derived::equals).orElse(false)) {
            keys.close();
            log.error("Stored public keys of user {} do not match the private keys; refusing to unlock",
                    account.getId());
            throw new KeyUnlockException("stored public keys do not match the private keys", null);
        }
    }
}
