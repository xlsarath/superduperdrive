package io.github.xlsarath.superduperdrive.service;

/**
 * The request is authenticated but the session holds no unlocked keys (for example after the
 * keyring was wiped). The user has to sign in again.
 */
public class KeysLockedException extends RuntimeException {

    public KeysLockedException() {
        super("no unlocked keyring in this session");
    }
}
