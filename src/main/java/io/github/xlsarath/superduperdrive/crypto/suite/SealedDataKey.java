package io.github.xlsarath.superduperdrive.crypto.suite;

/**
 * A freshly generated data key: the envelope to persist and the cipher to use it with.
 * Closing it closes the cipher.
 */
public record SealedDataKey(String suiteId, Envelope envelope, ItemCipher cipher) implements AutoCloseable {

    @Override
    public void close() {
        cipher.close();
    }
}
