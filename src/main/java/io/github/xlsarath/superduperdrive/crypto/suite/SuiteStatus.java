package io.github.xlsarath.superduperdrive.crypto.suite;

/** Lifecycle of a registered suite. */
public enum SuiteStatus {
    /** Used for all new encryptions. Exactly one suite has this status. */
    CURRENT,
    /** Still decrypts, never used for new data; items are re-keyed on the next login. */
    SUPPORTED,
    /** Pre-envelope data from an older version of the application; read once, then migrated. */
    LEGACY_DECRYPT_ONLY
}
