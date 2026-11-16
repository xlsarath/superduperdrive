package io.github.xlsarath.superduperdrive.crypto.keys;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPrivateKey;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * All private key material of one user, held as compact seeds in a single byte array:
 *
 * <pre>
 *   0x01 | X25519 scalar (32) | ML-KEM-768 seed d||z (64) | ML-DSA-65 seed xi (32) | index key (32)
 * </pre>
 *
 * <p>The index key is a 256-bit HMAC key used to derive blind, per-user lookup tags (for
 * example the duplicate-file-name check) without storing names in plaintext.
 *
 * <p>Expanded Bouncy Castle key objects are created per operation and dropped; {@link #close()}
 * zeroes the seeds. That is the most the JVM allows: copies made by the garbage collector or
 * inside Bouncy Castle cannot be wiped, which {@code docs/CRYPTO.md} states explicitly.
 */
public final class UserKeyMaterial implements AutoCloseable {

    private static final byte FORMAT_V1 = 0x01;
    private static final int X25519_OFFSET = 1;
    private static final int ML_KEM_OFFSET = X25519_OFFSET + HybridPrivateKey.X25519_SEED_BYTES;
    private static final int ML_DSA_OFFSET = ML_KEM_OFFSET + HybridPrivateKey.ML_KEM_SEED_BYTES;
    public static final int ML_DSA_SEED_BYTES = 32;
    private static final int INDEX_KEY_OFFSET = ML_DSA_OFFSET + ML_DSA_SEED_BYTES;
    public static final int INDEX_KEY_BYTES = 32;
    public static final int ENCODED_BYTES = INDEX_KEY_OFFSET + INDEX_KEY_BYTES;

    private final byte[] encoded;
    private volatile boolean destroyed;

    private UserKeyMaterial(byte[] encoded) {
        this.encoded = encoded;
    }

    public static UserKeyMaterial generate(SecureRandom random) {
        byte[] encoded = new byte[ENCODED_BYTES];
        random.nextBytes(encoded);
        encoded[0] = FORMAT_V1;
        return new UserKeyMaterial(encoded);
    }

    /** Parses the encoding produced by {@link #encode()}. The input array is copied, not adopted. */
    public static UserKeyMaterial decode(byte[] encoding) {
        if (encoding.length != ENCODED_BYTES || encoding[0] != FORMAT_V1) {
            throw new CryptoException("unsupported key bundle encoding");
        }
        return new UserKeyMaterial(encoding.clone());
    }

    /** Returns a fresh copy of the encoding; the caller must wipe it. */
    public byte[] encode() {
        checkAlive();
        return encoded.clone();
    }

    public HybridPrivateKey hybridPrivateKey() {
        byte[] x = slice(X25519_OFFSET, HybridPrivateKey.X25519_SEED_BYTES);
        byte[] m = slice(ML_KEM_OFFSET, HybridPrivateKey.ML_KEM_SEED_BYTES);
        try {
            return new HybridPrivateKey(x, m);
        } finally {
            Bytes.wipe(x, m);
        }
    }

    public MLDSAPrivateKeyParameters signingKey() {
        byte[] seed = slice(ML_DSA_OFFSET, ML_DSA_SEED_BYTES);
        try {
            return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, seed);
        } finally {
            Bytes.wipe(seed);
        }
    }

    /** Returns a copy of the index key; the caller must wipe it. */
    public byte[] indexKey() {
        return slice(INDEX_KEY_OFFSET, INDEX_KEY_BYTES);
    }

    public UserPublicKeys publicKeys() {
        return new UserPublicKeys(hybridPrivateKey().publicKey(), signingKey().getPublicKey());
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public void close() {
        destroyed = true;
        Bytes.wipe(encoded);
    }

    private byte[] slice(int offset, int length) {
        checkAlive();
        return Arrays.copyOfRange(encoded, offset, offset + length);
    }

    private void checkAlive() {
        if (destroyed) {
            throw new IllegalStateException("key material has been destroyed");
        }
    }

    @Override
    public String toString() {
        return "UserKeyMaterial[redacted]";
    }
}
