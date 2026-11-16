package io.github.xlsarath.superduperdrive.crypto.suite;

/**
 * Human-readable description of a suite, shown on the Security page and in the docs.
 *
 * @param id          stable identifier persisted with every ciphertext, for example
 *                    {@code HYB-X25519-MLKEM768-AES256GCM-v1}
 * @param version     format version of the envelope written by this suite
 * @param status      lifecycle status
 * @param keyExchange key establishment
 * @param kdf         key derivation
 * @param aead        content encryption
 * @param quantumSafe whether confidentiality holds against a quantum adversary
 */
public record SuiteDescriptor(String id, int version, SuiteStatus status, String keyExchange, String kdf,
                              String aead, boolean quantumSafe) {

    public SuiteDescriptor withStatus(SuiteStatus newStatus) {
        return new SuiteDescriptor(id, version, newStatus, keyExchange, kdf, aead, quantumSafe);
    }
}
