package io.github.xlsarath.superduperdrive.crypto.kem;

import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;

/**
 * Decapsulation key for {@link HybridKem}, expanded from compact seeds:
 * a 32-byte X25519 scalar and the 64-byte ML-KEM seed {@code (d || z)} from FIPS 203.
 *
 * <p>Instances are short-lived (one per operation) so that the long-lived copy of the secret
 * stays in a single wipeable byte array owned by the session keyring.
 */
public final class HybridPrivateKey {

    public static final int X25519_SEED_BYTES = X25519PrivateKeyParameters.KEY_SIZE;
    public static final int ML_KEM_SEED_BYTES = 64;

    private final X25519PrivateKeyParameters x25519;
    private final MLKEMPrivateKeyParameters mlKem;
    private final HybridPublicKey publicKey;

    public HybridPrivateKey(byte[] x25519Seed, byte[] mlKemSeed) {
        this.x25519 = new X25519PrivateKeyParameters(x25519Seed, 0);
        this.mlKem = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, mlKemSeed);
        this.publicKey = new HybridPublicKey(x25519.generatePublicKey().getEncoded(), mlKem.getPublicKey());
    }

    X25519PrivateKeyParameters x25519() {
        return x25519;
    }

    MLKEMPrivateKeyParameters mlKem() {
        return mlKem;
    }

    public HybridPublicKey publicKey() {
        return publicKey;
    }

    @Override
    public String toString() {
        return "HybridPrivateKey[redacted]";
    }
}
