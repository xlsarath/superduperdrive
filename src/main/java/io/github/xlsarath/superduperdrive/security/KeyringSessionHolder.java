package io.github.xlsarath.superduperdrive.security;

import io.github.xlsarath.superduperdrive.service.UnlockedKeyring;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionBindingListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * Session attribute that owns the {@link UnlockedKeyring}. When it is unbound (logout,
 * session expiry, session invalidation, or replacement by a new login) the keys are wiped.
 *
 * <p>Deliberately not {@link java.io.Serializable}: the servlet container never writes it to
 * disk, so unlocked keys cannot end up in a persisted session store.
 */
public final class KeyringSessionHolder implements HttpSessionBindingListener {

    static final String ATTRIBUTE = KeyringSessionHolder.class.getName();
    private static final Logger log = LoggerFactory.getLogger(KeyringSessionHolder.class);

    private final UnlockedKeyring keyring;

    private KeyringSessionHolder(UnlockedKeyring keyring) {
        this.keyring = keyring;
    }

    public static void store(HttpSession session, UnlockedKeyring keyring) {
        session.setAttribute(ATTRIBUTE, new KeyringSessionHolder(keyring));
    }

    public static Optional<UnlockedKeyring> find(HttpSession session) {
        if (session == null) {
            return Optional.empty();
        }
        Object holder = session.getAttribute(ATTRIBUTE);
        if (holder instanceof KeyringSessionHolder keyringHolder && !keyringHolder.keyring.isClosed()) {
            return Optional.of(keyringHolder.keyring);
        }
        return Optional.empty();
    }

    @Override
    public void valueUnbound(HttpSessionBindingEvent event) {
        keyring.close();
        log.info("Wiped session keyring of user {}", keyring.userId());
    }
}
