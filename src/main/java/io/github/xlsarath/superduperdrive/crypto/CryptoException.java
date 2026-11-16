package io.github.xlsarath.superduperdrive.crypto;

/**
 * Unchecked failure inside the cryptographic layer that is <em>not</em> an authentication
 * failure: malformed input, unsupported parameters, or an unexpected provider error.
 *
 * <p>Messages never contain key material, plaintext or ciphertext bytes.
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
