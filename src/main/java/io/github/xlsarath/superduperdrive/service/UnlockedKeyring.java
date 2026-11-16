package io.github.xlsarath.superduperdrive.service;

import io.github.xlsarath.superduperdrive.crypto.kem.HybridPrivateKey;
import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;
import io.github.xlsarath.superduperdrive.crypto.keys.UserPublicKeys;

import java.util.UUID;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

/**
 * A user's private keys, unlocked at login and held only in server memory for the lifetime of
 * the HTTP session. Closing it zeroes the seeds; a read/write lock guarantees that never
 * happens in the middle of an operation that is using them.
 *
 * <p>Public keys used for sealing come from here (derived from the private keys) rather than
 * from the database, so substituting a public key in the database cannot redirect new data to
 * an attacker's key.
 */
public final class UnlockedKeyring implements AutoCloseable {

    private final UUID userId;
    private final UserKeyMaterial keys;
    private final UserPublicKeys publicKeys;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private boolean closed;

    public UnlockedKeyring(UUID userId, UserKeyMaterial keys) {
        this.userId = userId;
        this.keys = keys;
        this.publicKeys = keys.publicKeys();
    }

    public UUID userId() {
        return userId;
    }

    public UserPublicKeys publicKeys() {
        return publicKeys;
    }

    public HybridPrivateKey hybridPrivateKey() {
        return use(UserKeyMaterial::hybridPrivateKey);
    }

    /** Runs {@code action} with the key material while guaranteeing it is not wiped concurrently. */
    public <T> T use(Function<UserKeyMaterial, T> action) {
        lock.readLock().lock();
        try {
            if (closed) {
                throw new KeysLockedException();
            }
            return action.apply(keys);
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean isClosed() {
        lock.readLock().lock();
        try {
            return closed;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            if (!closed) {
                closed = true;
                keys.close();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public String toString() {
        return "UnlockedKeyring[user=" + userId + (isClosed() ? ", closed" : "") + "]";
    }
}
