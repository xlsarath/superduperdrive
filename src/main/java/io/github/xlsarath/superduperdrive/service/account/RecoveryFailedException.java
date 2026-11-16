package io.github.xlsarath.superduperdrive.service.account;

/**
 * Account recovery failed. One generic exception for unknown user, locked account, malformed
 * key and wrong key, so the response does not reveal which.
 */
public class RecoveryFailedException extends RuntimeException {

    public RecoveryFailedException() {
        super("account recovery failed");
    }
}
