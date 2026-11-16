package io.github.xlsarath.superduperdrive.crypto.suite;

import io.github.xlsarath.superduperdrive.crypto.kem.HybridPrivateKey;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPublicKey;

/**
 * A suite that protects items with per-item data keys wrapped to the owner's public key.
 * Implementations are stateless and thread-safe.
 */
public interface EnvelopeSuite extends CryptoSuite {

    /** Generates a fresh DEK for {@code context} and wraps it to {@code recipient}. */
    SealedDataKey newDataKey(ItemContext context, HybridPublicKey recipient);

    /**
     * Unwraps the DEK of an existing item.
     *
     * @throws io.github.xlsarath.superduperdrive.crypto.IntegrityException if the envelope does not
     *         authenticate for this context and key
     */
    ItemCipher openDataKey(ItemContext context, Envelope envelope, HybridPrivateKey recipient);
}
