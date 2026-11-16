package io.github.xlsarath.superduperdrive.crypto.sign;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;
import io.github.xlsarath.superduperdrive.crypto.keys.UserPublicKeys;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * ML-DSA-65 (FIPS 204, "pure" mode) signatures over {@link FileManifest} statements.
 *
 * <p>The FIPS 204 context string {@value FileManifest#CONTEXT} provides domain separation, so a
 * manifest signature can never be replayed as a signature for any other purpose. Signing is
 * hedged (fresh randomness mixed with the deterministic nonce derivation), the FIPS 204
 * default. The statement already contains the SHA3-256 of the content, so the message passed
 * to ML-DSA is small and HashML-DSA is not needed.
 */
public final class ManifestSigner {

    public static final int SIGNATURE_BYTES = 3309;
    private static final byte[] CONTEXT = FileManifest.CONTEXT.getBytes(StandardCharsets.US_ASCII);

    private final SecureRandom random;

    public ManifestSigner(SecureRandom random) {
        this.random = random;
    }

    public byte[] sign(UserKeyMaterial keys, FileManifest manifest) {
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, new ParametersWithContext(new ParametersWithRandom(keys.signingKey(), random), CONTEXT));
        byte[] message = manifest.canonicalBytes();
        signer.update(message, 0, message.length);
        try {
            return signer.generateSignature();
        } catch (org.bouncycastle.crypto.CryptoException e) {
            throw new CryptoException("ML-DSA signing failed", e);
        }
    }

    /**
     * Verifies {@code signature} and that the manifest names {@code publicKey} as its signer.
     * Never throws for a bad signature; returns {@code false}.
     */
    public boolean verify(byte[] publicKey, FileManifest manifest, byte[] signature) {
        if (signature == null || signature.length != SIGNATURE_BYTES
                || publicKey == null || publicKey.length != UserPublicKeys.ML_DSA_65_PUBLIC_BYTES) {
            return false;
        }
        byte[] expectedFingerprint = UserPublicKeys.fingerprint(publicKey).getBytes(StandardCharsets.US_ASCII);
        if (!Bytes.constantTimeEquals(expectedFingerprint, manifest.signerKey().getBytes(StandardCharsets.US_ASCII))) {
            return false;
        }
        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, new ParametersWithContext(
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, publicKey), CONTEXT));
        byte[] message = manifest.canonicalBytes();
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }
}
