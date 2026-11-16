package io.github.xlsarath.superduperdrive.service.account;

import io.github.xlsarath.superduperdrive.config.DriveProperties;
import io.github.xlsarath.superduperdrive.domain.UserAccount;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.Optional;

/**
 * Per-account lockout: after {@code sdd.login.max-failures} consecutive failures the account is
 * locked for {@code sdd.login.lockout-duration}. While locked, Spring Security rejects the
 * login before checking the password, so guessing stops. Each update runs in its own
 * transaction (so it survives the failed request) and is retried on concurrent updates.
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);
    private static final int MAX_RETRIES = 3;

    private final UserAccountRepository users;
    private final DriveProperties.Login settings;
    private final TransactionTemplate requiresNew;
    private final Clock clock;

    public LoginAttemptService(UserAccountRepository users, DriveProperties properties,
                               PlatformTransactionManager transactionManager, Clock clock) {
        this.users = users;
        this.settings = properties.login();
        this.requiresNew = new TransactionTemplate(transactionManager);
        this.requiresNew.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.clock = clock;
    }

    public void recordFailure(String username) {
        withRetry(username, account -> {
            boolean locked = account.recordFailedLogin(settings.maxFailures(),
                    clock.instant().plus(settings.lockoutDuration()));
            if (locked) {
                log.warn("Locked user {} for {} after {} consecutive failures", account.getId(),
                        settings.lockoutDuration(), settings.maxFailures());
            } else {
                log.info("Failed login for user {} ({} of {})", account.getId(), account.getFailedLoginAttempts(),
                        settings.maxFailures());
            }
            return true;
        });
    }

    public void recordSuccess(String username) {
        withRetry(username, account -> {
            if (account.getFailedLoginAttempts() == 0 && account.getLockedUntil() == null) {
                return false;
            }
            account.clearFailedLogins();
            return true;
        });
    }

    private void withRetry(String username, java.util.function.Function<UserAccount, Boolean> change) {
        String normalized = AccountService.normalizeUsername(username);
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                requiresNew.executeWithoutResult(status -> {
                    Optional<UserAccount> account = users.findByUsername(normalized);
                    if (account.isPresent() && change.apply(account.get())) {
                        users.saveAndFlush(account.get());
                    }
                });
                return;
            } catch (OptimisticLockingFailureException e) {
                log.debug("Concurrent update of login attempts, retry {} of {}", attempt, MAX_RETRIES);
            }
        }
        log.warn("Gave up updating login attempts after {} concurrent-update retries", MAX_RETRIES);
    }
}
