package io.github.xlsarath.superduperdrive.crypto.kem;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import io.github.xlsarath.superduperdrive.crypto.support.CanonicalEncoder;
import io.github.xlsarath.superduperdrive.crypto.support.Hkdf;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Hybrid key encapsulation: X25519 (RFC 7748) in parallel with ML-KEM-768 (FIPS 203).
 *
 * <p>The two shared secrets are combined in the spirit of X-Wing
 * (draft-connolly-cfrg-xwing-kem): the KDF input contains <em>both</em> secrets and is bound
 * to both ciphertexts and both recipient public keys, so the derived key stays
 * IND-CCA secure as long as <em>either</em> component is secure:
 *
 * <pre>
 *   ss_X  = X25519(eph_sk, pk_X)                    ct_X = eph_pk           (32 bytes)
 *   ss_M, ct_M = ML-KEM-768.Encaps(pk_M)                                   (1088 bytes)
 *   KEK   = HKDF-SHA-512(
 *             salt = "SuperDuperDrive/HybridKEM/X25519-MLKEM768/v1",
 *             ikm  = ss_M || ss_X,
 *             info = LP(ct_M) || LP(ct_X) || LP(pk_M) || LP(pk_X) || LP(context),
 *             L    = 32)
 * </pre>
 *
 * <p>{@code LP} is the length-prefixed {@link CanonicalEncoder}. X-Wing itself omits
 * {@code ct_M}/{@code pk_M} because ML-KEM already binds them; including them costs one
 * extra SHA-512 pass over ~2.3 KB and removes that reliance. {@code context} binds the key to
 * the item (kind, id, owner, suite), so a KEM ciphertext cannot be transplanted onto another
 * item.
 *
 * <p>The encapsulation is the fixed-size concatenation {@code ct_X || ct_M} (1120 bytes).
 */
public final class HybridKem {

    public static final int CIPHERTEXT_BYTES = HybridPublicKey.X25519_BYTES + 1088;
    public static final int SHARED_KEY_BYTES = 32;
    private static final byte[] COMBINER_SALT =
            "SuperDuperDrive/HybridKEM/X25519-MLKEM768/v1".getBytes(StandardCharsets.US_ASCII);

    private final SecureRandom random;

    public HybridKem(SecureRandom random) {
        this.random = random;
    }

    /** Result of an encapsulation. The caller owns {@code sharedKey} and must wipe it. */
    public record Encapsulation(byte[] ciphertext, byte[] sharedKey) {
    }

    public Encapsulation encapsulate(HybridPublicKey recipient, byte[] context) {
        X25519PrivateKeyParameters ephemeral = new X25519PrivateKeyParameters(random);
        byte[] ctX = ephemeral.generatePublicKey().getEncoded();
        byte[] ssX = new byte[X25519PrivateKeyParameters.SECRET_SIZE];
        try {
            ephemeral.generateSecret(recipient.x25519Parameters(), ssX, 0);
        } catch (IllegalStateException e) {
            // RFC 7748 section 6.1: all-zero output means a small-order public key.
            throw new CryptoException("recipient X25519 public key is invalid", e);
        }

        SecretWithEncapsulation mlKem = new MLKEMGenerator(random).generateEncapsulated(recipient.mlKemParameters());
        byte[] ctM = mlKem.getEncapsulation();
        byte[] ssM = mlKem.getSecret();
        try {
            byte[] kek = combine(ssM, ssX, ctM, ctX, recipient.mlKem(), recipient.x25519(), context);
            return new Encapsulation(Bytes.concat(ctX, ctM), kek);
        } finally {
            Bytes.wipe(ssX, ssM);
            destroyQuietly(mlKem);
        }
    }

    /**
     * Recovers the shared key. ML-KEM uses implicit rejection, so a tampered ciphertext yields
     * a pseudorandom key rather than an error; the failure surfaces when the AEAD that uses this
     * key rejects its tag.
     */
    public byte[] decapsulate(HybridPrivateKey recipient, byte[] ciphertext, byte[] context) {
        if (ciphertext == null || ciphertext.length != CIPHERTEXT_BYTES) {
            throw new IntegrityException("hybrid KEM ciphertext has the wrong length");
        }
        byte[] ctX = Arrays.copyOfRange(ciphertext, 0, HybridPublicKey.X25519_BYTES);
        byte[] ctM = Arrays.copyOfRange(ciphertext, HybridPublicKey.X25519_BYTES, CIPHERTEXT_BYTES);

        byte[] ssX = new byte[X25519PrivateKeyParameters.SECRET_SIZE];
        try {
            recipient.x25519().generateSecret(new X25519PublicKeyParameters(ctX, 0), ssX, 0);
        } catch (IllegalStateException e) {
            throw new IntegrityException("hybrid KEM ciphertext carries an invalid X25519 share", e);
        }
        MLKEMPrivateKeyParameters mlKemKey = recipient.mlKem();
        byte[] ssM = new MLKEMExtractor(mlKemKey).extractSecret(ctM);
        try {
            return combine(ssM, ssX, ctM, ctX, recipient.publicKey().mlKem(), recipient.publicKey().x25519(), context);
        } finally {
            Bytes.wipe(ssX, ssM);
        }
    }

    private static byte[] combine(byte[] ssM, byte[] ssX, byte[] ctM, byte[] ctX, byte[] pkM, byte[] pkX,
                                  byte[] context) {
        byte[] ikm = Bytes.concat(ssM, ssX);
        byte[] info = CanonicalEncoder.create()
                .add(ctM).add(ctX).add(pkM).add(pkX).add(context)
                .toByteArray();
        try {
            return Hkdf.sha512(ikm, COMBINER_SALT, info, SHARED_KEY_BYTES);
        } finally {
            Bytes.wipe(ikm);
        }
    }

    private static void destroyQuietly(SecretWithEncapsulation secret) {
        try {
            secret.destroy();
        } catch (Exception ignored) {
            // Best effort: the secret bytes we copied were already wiped above.
        }
    }
}
