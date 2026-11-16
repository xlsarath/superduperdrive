package io.github.xlsarath.superduperdrive.crypto.keys;

import io.github.xlsarath.superduperdrive.crypto.kdf.Argon2Params;
import io.github.xlsarath.superduperdrive.crypto.kdf.Argon2idKdf;
import io.github.xlsarath.superduperdrive.crypto.support.AesGcm;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import io.github.xlsarath.superduperdrive.crypto.support.CanonicalEncoder;
import io.github.xlsarath.superduperdrive.crypto.support.Hkdf;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Wraps and unwraps {@link UserKeyMaterial} at rest.
 *
 * <p>The AES-256-GCM associated data binds the bundle to the user id, the wrap method, the
 * salt and the Argon2 cost, so a bundle cannot be moved to another account and its cost
 * parameters cannot be silently downgraded in the database.
 */
public final class KeyBundleProtector {

    private static final String AAD_LABEL = "SDD/KEYBUNDLE/v1";
    private static final String RECOVERY_INFO_LABEL = "SDD/RECOVERY-WRAP/v1";

    private final SecureRandom random;
    private final Argon2Params defaultArgon2;

    public KeyBundleProtector(SecureRandom random, Argon2Params defaultArgon2) {
        this.random = random;
        this.defaultArgon2 = defaultArgon2;
    }

    public Argon2Params defaultArgon2() {
        return defaultArgon2;
    }

    public WrappedKeyBundle wrapWithPassword(UUID userId, char[] password, UserKeyMaterial keys) {
        byte[] salt = randomBytes(WrappedKeyBundle.SALT_BYTES);
        byte[] kek = Argon2idKdf.derive(password, salt, defaultArgon2, Bytes.uuid(userId), AesGcm.KEY_BYTES);
        return seal(KeyWrapMethod.PASSWORD_ARGON2ID, userId, salt, defaultArgon2, kek, keys);
    }

    /** @throws io.github.xlsarath.superduperdrive.crypto.IntegrityException on a wrong password or tampering */
    public UserKeyMaterial unwrapWithPassword(UUID userId, char[] password, WrappedKeyBundle bundle) {
        requireMethod(bundle, KeyWrapMethod.PASSWORD_ARGON2ID);
        byte[] kek = Argon2idKdf.derive(password, bundle.salt(), bundle.argon2(), Bytes.uuid(userId), AesGcm.KEY_BYTES);
        return open(userId, kek, bundle);
    }

    public WrappedKeyBundle wrapWithRecoveryKey(UUID userId, RecoveryKey recoveryKey, UserKeyMaterial keys) {
        byte[] salt = randomBytes(WrappedKeyBundle.SALT_BYTES);
        byte[] kek = recoveryKek(userId, recoveryKey, salt);
        return seal(KeyWrapMethod.RECOVERY_KEY_HKDF, userId, salt, null, kek, keys);
    }

    /** @throws io.github.xlsarath.superduperdrive.crypto.IntegrityException on a wrong recovery key or tampering */
    public UserKeyMaterial unwrapWithRecoveryKey(UUID userId, RecoveryKey recoveryKey, WrappedKeyBundle bundle) {
        requireMethod(bundle, KeyWrapMethod.RECOVERY_KEY_HKDF);
        byte[] kek = recoveryKek(userId, recoveryKey, bundle.salt());
        return open(userId, kek, bundle);
    }

    private WrappedKeyBundle seal(KeyWrapMethod method, UUID userId, byte[] salt, Argon2Params argon2, byte[] kek,
                                  UserKeyMaterial keys) {
        byte[] nonce = AesGcm.newNonce(random);
        byte[] plaintext = keys.encode();
        try {
            byte[] ciphertext = AesGcm.seal(kek, nonce, aad(method, userId, salt, argon2), plaintext);
            return new WrappedKeyBundle(method, salt, argon2, nonce, ciphertext);
        } finally {
            Bytes.wipe(kek, plaintext);
        }
    }

    private UserKeyMaterial open(UUID userId, byte[] kek, WrappedKeyBundle bundle) {
        byte[] plaintext = null;
        try {
            plaintext = AesGcm.open(kek, bundle.nonce(),
                    aad(bundle.method(), userId, bundle.salt(), bundle.argon2()), bundle.ciphertext());
            return UserKeyMaterial.decode(plaintext);
        } finally {
            Bytes.wipe(kek, plaintext);
        }
    }

    private static byte[] recoveryKek(UUID userId, RecoveryKey recoveryKey, byte[] salt) {
        byte[] ikm = recoveryKey.keyBytes();
        try {
            byte[] info = CanonicalEncoder.create().add(RECOVERY_INFO_LABEL).add(userId).toByteArray();
            return Hkdf.sha512(ikm, salt, info, AesGcm.KEY_BYTES);
        } finally {
            Bytes.wipe(ikm);
        }
    }

    private static byte[] aad(KeyWrapMethod method, UUID userId, byte[] salt, Argon2Params argon2) {
        CanonicalEncoder aad = CanonicalEncoder.create()
                .add(AAD_LABEL)
                .add(method.id())
                .add(userId)
                .add(salt);
        if (argon2 != null) {
            aad.add(argon2.memoryKib()).add(argon2.iterations()).add(argon2.parallelism());
        }
        return aad.toByteArray();
    }

    private static void requireMethod(WrappedKeyBundle bundle, KeyWrapMethod expected) {
        if (bundle.method() != expected) {
            throw new IllegalArgumentException("expected a " + expected.id() + " bundle");
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
