package io.github.xlsarath.superduperdrive.crypto.kem;

import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.util.Arrays;

/**
 * Recipient public key for the X25519 + ML-KEM-768 hybrid KEM.
 *
 * @param x25519 32-byte X25519 public key (RFC 7748)
 * @param mlKem  1184-byte ML-KEM-768 encapsulation key (FIPS 203)
 */
public record HybridPublicKey(byte[] x25519, byte[] mlKem) {

    public static final int X25519_BYTES = X25519PublicKeyParameters.KEY_SIZE;
    public static final int ML_KEM_768_BYTES = 1184;

    public HybridPublicKey {
        x25519 = Bytes.requireLength(x25519, X25519_BYTES, "X25519 public key").clone();
        mlKem = Bytes.requireLength(mlKem, ML_KEM_768_BYTES, "ML-KEM-768 public key").clone();
    }

    @Override
    public byte[] x25519() {
        return x25519.clone();
    }

    @Override
    public byte[] mlKem() {
        return mlKem.clone();
    }

    X25519PublicKeyParameters x25519Parameters() {
        return new X25519PublicKeyParameters(x25519, 0);
    }

    MLKEMPublicKeyParameters mlKemParameters() {
        return new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, mlKem);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof HybridPublicKey that
                && Arrays.equals(x25519, that.x25519)
                && Arrays.equals(mlKem, that.mlKem);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(x25519) + Arrays.hashCode(mlKem);
    }

    @Override
    public String toString() {
        return "HybridPublicKey[X25519+ML-KEM-768]";
    }
}
