package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemCipher;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.crypto.suite.LegacyAesEcbCredentialSuite;
import io.github.xlsarath.superduperdrive.crypto.suite.SealedDataKey;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import io.github.xlsarath.superduperdrive.domain.Credential;
import io.github.xlsarath.superduperdrive.repository.CredentialRepository;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.ItemNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static io.github.xlsarath.superduperdrive.service.item.ItemCrypto.string;
import static io.github.xlsarath.superduperdrive.service.item.ItemCrypto.utf8;

/** Encrypted website credentials, including migration of rows from the 2020 AES-ECB scheme. */
@Service
public class CredentialService implements SealedItemHandler {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);
    private static final int PREVIEW_CHARS = 24;

    private final CredentialRepository credentials;
    private final ItemCrypto crypto;
    private final Clock clock;

    public CredentialService(CredentialRepository credentials, ItemCrypto crypto, Clock clock) {
        this.credentials = credentials;
        this.crypto = crypto;
        this.clock = clock;
    }

    @Override
    public ItemKind kind() {
        return ItemKind.CREDENTIAL;
    }

    @Transactional(readOnly = true)
    public List<CredentialView> list(ActiveUser user) {
        return credentials.findAllByOwnerIdOrderByCreatedAtAsc(user.id()).stream().map(c -> view(user, c)).toList();
    }

    /** Decrypts one password for display. */
    @Transactional(readOnly = true)
    public String reveal(ActiveUser user, UUID id) {
        Credential credential = find(user, id);
        String password = decrypt(user, credential).password();
        log.info("Revealed password of credential {} for user {}", id, user.id());
        return password;
    }

    /**
     * Creates ({@code id == null}) or updates a credential. On update, a {@code null} or blank
     * password keeps the stored one, so the edit form never needs the plaintext.
     */
    @Transactional
    public UUID save(ActiveUser user, UUID id, String url, String username, String password) {
        boolean keepPassword = password == null || password.isEmpty();
        if (id == null && keepPassword) {
            throw new IllegalArgumentException("a new credential needs a password");
        }
        Credential credential = id == null ? new Credential(UUID.randomUUID(), user.id()) : find(user, id);
        String effectivePassword = keepPassword ? decrypt(user, credential).password() : password;
        seal(user, credential, new Plain(url, username, effectivePassword));
        credentials.save(credential);
        log.info("{} credential {} for user {} with suite {}", id == null ? "Created" : "Updated", credential.getId(),
                user.id(), credential.getSuiteId());
        return credential.getId();
    }

    @Transactional
    public void delete(ActiveUser user, UUID id) {
        credentials.delete(find(user, id));
        log.info("Deleted credential {} for user {}", id, user.id());
    }

    @Override
    @Transactional(readOnly = true)
    public List<UUID> outdatedItemIds(ActiveUser user) {
        return credentials.findAllByOwnerIdAndSuiteIdNot(user.id(), crypto.currentSuiteId()).stream()
                .map(Credential::getId).toList();
    }

    @Override
    @Transactional
    public void rekey(ActiveUser user, UUID itemId) {
        Credential credential = find(user, itemId);
        String previous = credential.getSuiteId();
        seal(user, credential, decrypt(user, credential));
        credentials.save(credential);
        log.info("Re-keyed credential {} for user {}: {} -> {}", itemId, user.id(), previous, credential.getSuiteId());
    }

    @Override
    @Transactional(readOnly = true)
    public List<SecurityItemView> describe(ActiveUser user) {
        return credentials.findAllByOwnerIdOrderByCreatedAtAsc(user.id()).stream().map(credential -> {
            CredentialView view = view(user, credential);
            var suite = crypto.registry().descriptor(credential.getSuiteId());
            return new SecurityItemView(ItemKind.CREDENTIAL, credential.getId(), view.url(), credential.getSuiteId(),
                    crypto.registry().isCurrent(credential.getSuiteId()), suite.quantumSafe(),
                    credential.getSealedAt(), credential.getMigratedFromSuite().orElse(null),
                    SignatureStatus.NOT_APPLICABLE, view.readable());
        }).toList();
    }

    private void seal(ActiveUser user, Credential credential, Plain plain) {
        try (SealedDataKey key = crypto.newDataKey(credential, user)) {
            credential.seal(key.suiteId(), key.envelope(),
                    key.cipher().encryptField(Credential.FIELD_URL, utf8(plain.url())),
                    key.cipher().encryptField(Credential.FIELD_USERNAME, utf8(plain.username())),
                    key.cipher().encryptField(Credential.FIELD_PASSWORD, utf8(plain.password())),
                    clock.instant());
        }
    }

    private Plain decrypt(ActiveUser user, Credential credential) {
        if (credential.isLegacy()) {
            LegacyAesEcbCredentialSuite legacy = crypto.registry()
                    .require(credential.getSuiteId(), LegacyAesEcbCredentialSuite.class);
            byte[] password = legacy.decrypt(credential.getLegacyPassword(), credential.getLegacyKey());
            try {
                return new Plain(credential.getLegacyUrl(), credential.getLegacyUsername(), string(password));
            } finally {
                Bytes.wipe(password);
            }
        }
        try (ItemCipher cipher = crypto.open(credential, user)) {
            return new Plain(
                    string(cipher.decryptField(Credential.FIELD_URL, credential.getUrlCiphertext())),
                    string(cipher.decryptField(Credential.FIELD_USERNAME, credential.getUsernameCiphertext())),
                    string(cipher.decryptField(Credential.FIELD_PASSWORD, credential.getPasswordCiphertext())));
        }
    }

    private CredentialView view(ActiveUser user, Credential credential) {
        try {
            Plain plain = decrypt(user, credential);
            String preview = credential.isLegacy()
                    ? credential.getLegacyPassword()
                    : Base64.getEncoder().encodeToString(credential.getPasswordCiphertext());
            return new CredentialView(credential.getId(), plain.url(), plain.username(),
                    preview.substring(0, Math.min(PREVIEW_CHARS, preview.length())), credential.getSuiteId(), true);
        } catch (CryptoException e) {
            log.warn("Credential {} of user {} failed to decrypt ({}): {}", credential.getId(), user.id(),
                    credential.getSuiteId(), e.getMessage());
            return new CredentialView(credential.getId(), "Unreadable credential", "", "", credential.getSuiteId(),
                    false);
        }
    }

    private Credential find(ActiveUser user, UUID id) {
        return credentials.findByIdAndOwnerId(id, user.id())
                .orElseThrow(() -> new ItemNotFoundException(ItemKind.CREDENTIAL, id));
    }

    /** Decrypted credential fields; never logged. */
    private record Plain(String url, String username, String password) {
        @Override
        public String toString() {
            return "Plain[redacted]";
        }
    }
}
