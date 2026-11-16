package io.github.xlsarath.superduperdrive.service.account;

/**
 * The password verified against the hash, but the wrapped key bundle did not open or did not
 * match the stored public keys. Indicates database corruption or tampering.
 */
public class KeyUnlockException extends RuntimeException {

    public KeyUnlockException(String message, Throwable cause) {
        super(message, cause);
    }
}
