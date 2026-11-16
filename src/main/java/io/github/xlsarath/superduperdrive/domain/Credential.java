package io.github.xlsarath.superduperdrive.domain;

import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * Website credential. Sealed rows encrypt URL, username and password. Rows imported from the
 * 2020 schema carry the {@code legacy_*} columns until the owner's next login migrates them.
 */
@Entity
@Table(name = "credential")
public class Credential extends SealedItem {

    public static final String FIELD_URL = "url";
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_PASSWORD = "password";

    @Column(name = "url_ciphertext")
    private byte[] urlCiphertext;

    @Column(name = "username_ciphertext")
    private byte[] usernameCiphertext;

    @Column(name = "password_ciphertext")
    private byte[] passwordCiphertext;

    @Column(name = "legacy_url", length = 2048)
    private String legacyUrl;

    @Column(name = "legacy_username", length = 256)
    private String legacyUsername;

    @Column(name = "legacy_key", length = 64)
    private String legacyKey;

    @Column(name = "legacy_password", length = 4096)
    private String legacyPassword;

    protected Credential() {
    }

    public Credential(UUID id, UUID ownerId) {
        super(id, ownerId, null);
    }

    /** A row as the 2020 application stored it: URL and username in clear, password AES-ECB. */
    public static Credential legacy(UUID id, UUID ownerId, String legacySuiteId, String url, String username,
                                    String key, String encryptedPassword) {
        Credential credential = new Credential();
        credential.initLegacy(id, ownerId, legacySuiteId);
        credential.legacyUrl = url;
        credential.legacyUsername = username;
        credential.legacyKey = key;
        credential.legacyPassword = encryptedPassword;
        return credential;
    }

    private void initLegacy(UUID id, UUID ownerId, String legacySuiteId) {
        setIdentity(id, ownerId, legacySuiteId);
    }

    @Override
    public ItemKind kind() {
        return ItemKind.CREDENTIAL;
    }

    public boolean isLegacy() {
        return legacyPassword != null;
    }

    /** Seals (or re-seals) the credential and drops any legacy columns. */
    public void seal(String suiteId, Envelope envelope, byte[] urlCiphertext, byte[] usernameCiphertext,
                     byte[] passwordCiphertext, Instant now) {
        applySeal(suiteId, envelope, now);
        this.urlCiphertext = urlCiphertext.clone();
        this.usernameCiphertext = usernameCiphertext.clone();
        this.passwordCiphertext = passwordCiphertext.clone();
        this.legacyUrl = null;
        this.legacyUsername = null;
        this.legacyKey = null;
        this.legacyPassword = null;
    }

    public byte[] getUrlCiphertext() {
        return urlCiphertext == null ? null : urlCiphertext.clone();
    }

    public byte[] getUsernameCiphertext() {
        return usernameCiphertext == null ? null : usernameCiphertext.clone();
    }

    public byte[] getPasswordCiphertext() {
        return passwordCiphertext == null ? null : passwordCiphertext.clone();
    }

    public String getLegacyUrl() {
        return legacyUrl;
    }

    public String getLegacyUsername() {
        return legacyUsername;
    }

    public String getLegacyKey() {
        return legacyKey;
    }

    public String getLegacyPassword() {
        return legacyPassword;
    }
}
