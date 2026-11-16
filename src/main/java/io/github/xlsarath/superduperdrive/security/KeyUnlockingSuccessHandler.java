package io.github.xlsarath.superduperdrive.security;

import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.account.AccountService;
import io.github.xlsarath.superduperdrive.service.account.KeyUnlockException;
import io.github.xlsarath.superduperdrive.service.account.UnlockResult;
import io.github.xlsarath.superduperdrive.service.item.CryptoMigrationService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.io.IOException;

/**
 * Runs after Spring Security has verified the password (and rotated the session id). Uses the
 * same password, still present in the login request, to unwrap the user's private keys into
 * server memory, then migrates any items not yet on the current crypto suite.
 *
 * <p>If the keys cannot be unlocked the login is rolled back: being signed in without keys
 * would be useless and confusing.
 */
public final class KeyUnlockingSuccessHandler implements AuthenticationSuccessHandler {

    /** Session attribute holding a recovery key that must be shown once (keys provisioned at login). */
    public static final String PENDING_RECOVERY_KEY = KeyUnlockingSuccessHandler.class.getName() + ".recoveryKey";

    private static final Logger log = LoggerFactory.getLogger(KeyUnlockingSuccessHandler.class);

    private final AccountService accounts;
    private final CryptoMigrationService migration;
    private final SavedRequestAwareAuthenticationSuccessHandler next = new SavedRequestAwareAuthenticationSuccessHandler();

    public KeyUnlockingSuccessHandler(AccountService accounts, CryptoMigrationService migration) {
        this.accounts = accounts;
        this.migration = migration;
        this.next.setDefaultTargetUrl("/files");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        DriveUserDetails principal = (DriveUserDetails) authentication.getPrincipal();
        String presented = request.getParameter("password");
        char[] password = presented == null ? new char[0] : presented.toCharArray();
        UnlockResult result;
        try {
            result = accounts.unlock(principal.id(), password);
        } catch (KeyUnlockException e) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
            response.sendRedirect(request.getContextPath() + "/login?keyerror");
            return;
        } finally {
            Bytes.wipe(password);
        }

        HttpSession session = request.getSession();
        KeyringSessionHolder.store(session, result.keyring());
        log.info("User {} signed in; keys unlocked into session memory", principal.id());

        ActiveUser user = new ActiveUser(principal.id(), principal.getUsername(), result.keyring());
        try {
            migration.migrateOutdatedItems(user);
        } catch (RuntimeException e) {
            log.error("Post-login crypto migration for user {} failed", principal.id(), e);
        }

        if (result.issuedRecoveryKey().isPresent()) {
            session.setAttribute(PENDING_RECOVERY_KEY, result.issuedRecoveryKey().get());
            response.sendRedirect(request.getContextPath() + "/account/recovery-key");
            return;
        }
        next.onAuthenticationSuccess(request, response, authentication);
    }
}
