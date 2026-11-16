package io.github.xlsarath.superduperdrive.crypto.suite;

import io.github.xlsarath.superduperdrive.crypto.support.Bytes;

/**
 * Per-item key envelope: the hybrid KEM ciphertext and the data-encryption key (DEK) wrapped
 * under the KEM-derived key-encryption key.
 *
 * @param formatVersion envelope format version (bound into the AAD)
 * @param kemCiphertext {@code ct_X || ct_M}
 * @param wrapNonce     AES-GCM nonce used to wrap the DEK
 * @param wrappedDek    AES-256-GCM ciphertext and tag of the 32-byte DEK
 */
public record Envelope(int formatVersion, byte[] kemCiphertext, byte[] wrapNonce, byte[] wrappedDek) {

    public Envelope {
        kemCiphertext = kemCiphertext.clone();
        wrapNonce = wrapNonce.clone();
        wrappedDek = wrappedDek.clone();
    }

    @Override
    public byte[] kemCiphertext() {
        return kemCiphertext.clone();
    }

    @Override
    public byte[] wrapNonce() {
        return wrapNonce.clone();
    }

    @Override
    public byte[] wrappedDek() {
        return wrappedDek.clone();
    }

    public int size() {
        return kemCiphertext.length + wrapNonce.length + wrappedDek.length;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Envelope that
                && formatVersion == that.formatVersion
                && Bytes.constantTimeEquals(kemCiphertext, that.kemCiphertext)
                && Bytes.constantTimeEquals(wrapNonce, that.wrapNonce)
                && Bytes.constantTimeEquals(wrappedDek, that.wrappedDek);
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(wrappedDek);
    }

    @Override
    public String toString() {
        return "Envelope[v" + formatVersion + ", " + size() + " bytes]";
    }
}
