package io.github.xlsarath.superduperdrive.security;

import io.github.xlsarath.superduperdrive.domain.UserAccount;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import io.github.xlsarath.superduperdrive.service.account.AccountService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;

/**
 * Loads accounts for Spring Security and persists password-hash upgrades (legacy PBKDF2 to
 * Argon2id, or weaker to stronger Argon2id parameters) after a successful login.
 */
@Service
public class DriveUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    private static final Logger log = LoggerFactory.getLogger(DriveUserDetailsService.class);

    private final UserAccountRepository users;
    private final Clock clock;

    public DriveUserDetailsService(UserAccountRepository users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        UserAccount account = users.findByUsername(AccountService.normalizeUsername(username))
                .orElseThrow(() -> new UsernameNotFoundException("unknown user"));
        return toDetails(account);
    }

    @Override
    @Transactional
    public UserDetails updatePassword(UserDetails user, String newPasswordHash) {
        UserAccount account = users.findById(((DriveUserDetails) user).id())
                .orElseThrow(() -> new UsernameNotFoundException("account disappeared during login"));
        String previousScheme = scheme(account.getPasswordHash());
        account.changePasswordHash(newPasswordHash);
        users.save(account);
        log.info("Upgraded password hash of user {} from {} to {}", account.getId(), previousScheme,
                scheme(newPasswordHash));
        return toDetails(account);
    }

    private DriveUserDetails toDetails(UserAccount account) {
        return new DriveUserDetails(account.getId(), account.getUsername(), account.getPasswordHash(),
                !account.isLockedAt(clock.instant()));
    }

    /** The {@code {id}} prefix of a delegating-encoder hash, safe to log. */
    private static String scheme(String hash) {
        int end = hash.indexOf('}');
        return hash.startsWith("{") && end > 0 ? hash.substring(1, end) : "unknown";
    }
}
