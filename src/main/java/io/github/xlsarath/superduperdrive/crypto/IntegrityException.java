package io.github.xlsarath.superduperdrive.crypto;

/**
 * Authentication failure: an AEAD tag, a signature or a stream framing check did not verify.
 *
 * <p>This deliberately does not say <em>why</em> verification failed (wrong key, tampered
 * ciphertext, swapped associated data, truncation). Distinguishing those cases to a caller
 * would only help an attacker; the log line at the call site carries the item context.
 */
public class IntegrityException extends CryptoException {

    public IntegrityException(String message) {
        super(message);
    }

    public IntegrityException(String message, Throwable cause) {
        super(message, cause);
    }
}
