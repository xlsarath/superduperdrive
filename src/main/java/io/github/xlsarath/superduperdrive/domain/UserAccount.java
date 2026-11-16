package io.github.xlsarath.superduperdrive.domain;

import io.github.xlsarath.superduperdrive.crypto.kem.HybridPublicKey;
import io.github.xlsarath.superduperdrive.crypto.keys.UserPublicKeys;
import io.github.xlsarath.superduperdrive.crypto.keys.WrappedKeyBundle;
import jakarta.persistence.AttributeOverride;
import jakarta.persistence.AttributeOverrides;
import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * A registered user. Holds the password hash, lockout state, public keys and two wrapped
 * copies of the private keys (password and recovery key). Private keys never appear here in
 * plaintext.
 */
@Entity
@Table(name = "user_account")
@EntityListeners(AuditingEntityListener.class)
public class UserAccount {

    /** Identifies the key set a user holds; bumped if the set of user key algorithms changes. */
    public static final String KEY_SUITE = "USERKEYS-X25519-MLKEM768-MLDSA65-v1";

    @Id
    private UUID id;

    @Column(nullable = false, length = 32, updatable = false)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 512)
    private String passwordHash;

    @Column(name = "first_name", nullable = false, length = 64)
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 64)
    private String lastName;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "key_suite", length = 64)
    private String keySuite;

    @Column(name = "x25519_public_key")
    private byte[] x25519PublicKey;

    @Column(name = "ml_kem_public_key")
    private byte[] mlKemPublicKey;

    @Column(name = "ml_dsa_public_key")
    private byte[] mlDsaPublicKey;

    @Column(name = "keys_created_at")
    private Instant keysCreatedAt;

    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "method", column = @Column(name = "pw_wrap_method")),
            @AttributeOverride(name = "salt", column = @Column(name = "pw_wrap_salt")),
            @AttributeOverride(name = "argon2MemoryKib", column = @Column(name = "pw_wrap_argon2_memory_kib")),
            @AttributeOverride(name = "argon2Iterations", column = @Column(name = "pw_wrap_argon2_iterations")),
            @AttributeOverride(name = "argon2Parallelism", column = @Column(name = "pw_wrap_argon2_parallelism")),
            @AttributeOverride(name = "nonce", column = @Column(name = "pw_wrap_nonce")),
            @AttributeOverride(name = "ciphertext", column = @Column(name = "pw_wrap_ciphertext"))
    })
    private WrappedKeyColumns passwordWrappedKeys;

    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "method", column = @Column(name = "rk_wrap_method")),
            @AttributeOverride(name = "salt", column = @Column(name = "rk_wrap_salt")),
            @AttributeOverride(name = "argon2MemoryKib", column = @Column(name = "rk_wrap_argon2_memory_kib")),
            @AttributeOverride(name = "argon2Iterations", column = @Column(name = "rk_wrap_argon2_iterations")),
            @AttributeOverride(name = "argon2Parallelism", column = @Column(name = "rk_wrap_argon2_parallelism")),
            @AttributeOverride(name = "nonce", column = @Column(name = "rk_wrap_nonce")),
            @AttributeOverride(name = "ciphertext", column = @Column(name = "rk_wrap_ciphertext"))
    })
    private WrappedKeyColumns recoveryWrappedKeys;

    @Column(name = "recovery_key_issued_at")
    private Instant recoveryKeyIssuedAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    private Long version;

    protected UserAccount() {
    }

    public UserAccount(UUID id, String username, String passwordHash, String firstName, String lastName) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void changePasswordHash(String newHash) {
        this.passwordHash = newHash;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    // --- lockout -----------------------------------------------------------------------------

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public boolean isLockedAt(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /** Records a failed attempt; returns {@code true} if this attempt triggered a lock. */
    public boolean recordFailedLogin(int maxAttempts, Instant lockUntil) {
        failedLoginAttempts++;
        if (failedLoginAttempts >= maxAttempts) {
            lockedUntil = lockUntil;
            failedLoginAttempts = 0;
            return true;
        }
        return false;
    }

    public void clearFailedLogins() {
        failedLoginAttempts = 0;
        lockedUntil = null;
    }

    // --- keys --------------------------------------------------------------------------------

    public boolean hasKeys() {
        return keySuite != null && passwordWrappedKeys != null && passwordWrappedKeys.isPresent();
    }

    public void installKeys(UserPublicKeys publicKeys, WrappedKeyBundle passwordBundle,
                            WrappedKeyBundle recoveryBundle, Instant now) {
        this.keySuite = KEY_SUITE;
        this.x25519PublicKey = publicKeys.encryptionKey().x25519();
        this.mlKemPublicKey = publicKeys.encryptionKey().mlKem();
        this.mlDsaPublicKey = publicKeys.mlDsa();
        this.keysCreatedAt = now;
        replacePasswordWrappedKeys(passwordBundle);
        replaceRecoveryWrappedKeys(recoveryBundle, now);
    }

    public void replacePasswordWrappedKeys(WrappedKeyBundle bundle) {
        this.passwordWrappedKeys = WrappedKeyColumns.of(bundle);
    }

    public void replaceRecoveryWrappedKeys(WrappedKeyBundle bundle, Instant now) {
        this.recoveryWrappedKeys = WrappedKeyColumns.of(bundle);
        this.recoveryKeyIssuedAt = now;
    }

    public Optional<UserPublicKeys> publicKeys() {
        if (!hasKeys()) {
            return Optional.empty();
        }
        return Optional.of(new UserPublicKeys(new HybridPublicKey(x25519PublicKey, mlKemPublicKey), mlDsaPublicKey));
    }

    public Optional<WrappedKeyBundle> passwordWrappedKeys() {
        return passwordWrappedKeys != null && passwordWrappedKeys.isPresent()
                ? Optional.of(passwordWrappedKeys.toBundle()) : Optional.empty();
    }

    public Optional<WrappedKeyBundle> recoveryWrappedKeys() {
        return recoveryWrappedKeys != null && recoveryWrappedKeys.isPresent()
                ? Optional.of(recoveryWrappedKeys.toBundle()) : Optional.empty();
    }

    public String getKeySuite() {
        return keySuite;
    }

    public Instant getKeysCreatedAt() {
        return keysCreatedAt;
    }

    public Instant getRecoveryKeyIssuedAt() {
        return recoveryKeyIssuedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Long getVersion() {
        return version;
    }
}
