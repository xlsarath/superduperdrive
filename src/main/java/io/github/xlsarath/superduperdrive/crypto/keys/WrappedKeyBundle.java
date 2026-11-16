package io.github.xlsarath.superduperdrive.crypto.keys;

import io.github.xlsarath.superduperdrive.crypto.kdf.Argon2Params;
import io.github.xlsarath.superduperdrive.crypto.support.AesGcm;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;

/**
 * A user's {@link UserKeyMaterial} encrypted under a password- or recovery-derived key.
 *
 * @param method     how the wrapping key was derived
 * @param salt       KDF salt (32 random bytes)
 * @param argon2     Argon2id cost; {@code null} for {@link KeyWrapMethod#RECOVERY_KEY_HKDF}
 * @param nonce      AES-GCM nonce
 * @param ciphertext AES-256-GCM ciphertext and tag of the encoded key material
 */
public record WrappedKeyBundle(KeyWrapMethod method, byte[] salt, Argon2Params argon2, byte[] nonce,
                               byte[] ciphertext) {

    public static final int SALT_BYTES = 32;

    public WrappedKeyBundle {
        Bytes.requireLength(salt, SALT_BYTES, "key bundle salt");
        Bytes.requireLength(nonce, AesGcm.NONCE_BYTES, "key bundle nonce");
        if (method == KeyWrapMethod.PASSWORD_ARGON2ID && argon2 == null) {
            throw new IllegalArgumentException("password-wrapped bundles require Argon2 parameters");
        }
        if (method == KeyWrapMethod.RECOVERY_KEY_HKDF && argon2 != null) {
            throw new IllegalArgumentException("recovery-wrapped bundles do not use Argon2");
        }
        salt = salt.clone();
        nonce = nonce.clone();
        ciphertext = ciphertext.clone();
    }

    @Override
    public byte[] salt() {
        return salt.clone();
    }

    @Override
    public byte[] nonce() {
        return nonce.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    /** Human-readable description for the Security page, e.g. "Argon2id (64 MiB, t=3, p=1) + AES-256-GCM". */
    public String describe() {
        String kek = argon2 == null ? "HKDF-SHA-512 recovery key"
                : "Argon2id (%s, t=%d, p=%d)".formatted(argon2.memoryKib() % 1024 == 0
                        ? argon2.memoryKib() / 1024 + " MiB" : argon2.memoryKib() + " KiB",
                argon2.iterations(), argon2.parallelism());
        return kek + " + AES-256-GCM";
    }

    @Override
    public String toString() {
        return "WrappedKeyBundle[" + method.id() + (argon2 == null ? "" : ", " + argon2.describe()) + "]";
    }
}
