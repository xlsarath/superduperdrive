package io.github.xlsarath.superduperdrive.service.account;

import io.github.xlsarath.superduperdrive.service.UnlockedKeyring;

import java.util.Optional;

/**
 * Outcome of unlocking at login.
 *
 * @param keyring            the unlocked keys, to be kept in the session
 * @param issuedRecoveryKey  present only when keys were provisioned during this login (accounts
 *                           migrated from the 2020 schema); must be shown to the user once
 */
public record UnlockResult(UnlockedKeyring keyring, Optional<String> issuedRecoveryKey) {

    @Override
    public String toString() {
        return "UnlockResult[" + keyring + ", recoveryKeyIssued=" + issuedRecoveryKey.isPresent() + "]";
    }
}
