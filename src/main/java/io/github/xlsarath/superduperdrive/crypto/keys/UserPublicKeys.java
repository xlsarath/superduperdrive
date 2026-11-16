package io.github.xlsarath.superduperdrive.crypto.keys;

import io.github.xlsarath.superduperdrive.crypto.kem.HybridPublicKey;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.util.Arrays;

/**
 * A user's public keys: the hybrid KEM recipient key and the ML-DSA-65 verification key.
 */
public record UserPublicKeys(HybridPublicKey encryptionKey, byte[] mlDsa) {

    public static final int ML_DSA_65_PUBLIC_BYTES = 1952;

    public UserPublicKeys {
        mlDsa = Bytes.requireLength(mlDsa, ML_DSA_65_PUBLIC_BYTES, "ML-DSA-65 public key").clone();
    }

    @Override
    public byte[] mlDsa() {
        return mlDsa.clone();
    }

    /** SHA3-256 over the encoded ML-DSA-65 public key, hex encoded. Shown in the UI and manifests. */
    public String signingKeyFingerprint() {
        return fingerprint(mlDsa);
    }

    /** SHA3-256 over {@code pk_X || pk_M}, hex encoded. */
    public String encryptionKeyFingerprint() {
        return fingerprint(Bytes.concat(encryptionKey.x25519(), encryptionKey.mlKem()));
    }

    public static String fingerprint(byte[] encodedKey) {
        SHA3Digest sha3 = new SHA3Digest(256);
        sha3.update(encodedKey, 0, encodedKey.length);
        byte[] out = new byte[32];
        sha3.doFinal(out, 0);
        return Bytes.hex(out);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof UserPublicKeys that
                && encryptionKey.equals(that.encryptionKey)
                && Arrays.equals(mlDsa, that.mlDsa);
    }

    @Override
    public int hashCode() {
        return 31 * encryptionKey.hashCode() + Arrays.hashCode(mlDsa);
    }

    @Override
    public String toString() {
        return "UserPublicKeys[X25519+ML-KEM-768, ML-DSA-65]";
    }
}
