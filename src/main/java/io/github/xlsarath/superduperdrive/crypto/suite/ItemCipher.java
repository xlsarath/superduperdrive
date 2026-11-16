package io.github.xlsarath.superduperdrive.crypto.suite;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Symmetric operations under one item's data-encryption key. Obtained from an
 * {@link EnvelopeSuite}; must be closed to wipe the key.
 */
public interface ItemCipher extends AutoCloseable {

    /** Encrypts one named field (for example {@code "title"}); the name is bound into the AAD. */
    byte[] encryptField(String field, byte[] plaintext);

    /** @throws io.github.xlsarath.superduperdrive.crypto.IntegrityException if the field does not authenticate */
    byte[] decryptField(String field, byte[] ciphertext);

    /** Wraps {@code sink} so that everything written is encrypted; closing it writes the final segment. */
    OutputStream encryptingStream(OutputStream sink) throws IOException;

    /** Wraps {@code source} so that reads return authenticated plaintext. */
    InputStream decryptingStream(InputStream source);

    @Override
    void close();
}
