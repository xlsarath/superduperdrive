package io.github.xlsarath.superduperdrive.crypto.suite;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;

/** A persisted suite id is unknown, or the suite cannot perform the requested operation. */
public class UnsupportedSuiteException extends CryptoException {

    public UnsupportedSuiteException(String message) {
        super(message);
    }
}
