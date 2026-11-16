package io.github.xlsarath.superduperdrive.crypto.support;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Injective encoding for associated data and KDF inputs.
 *
 * <p>Every element is written as a 4-byte big-endian length followed by its bytes, so two
 * different sequences of elements can never produce the same encoding (no "ab"+"c" vs
 * "a"+"bc" ambiguity). All AAD, HKDF {@code info} and signature-context values in this code
 * base go through this one class.
 */
public final class CanonicalEncoder {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream(128);

    public static CanonicalEncoder create() {
        return new CanonicalEncoder();
    }

    public CanonicalEncoder add(byte[] value) {
        writeInt(value.length);
        out.writeBytes(value);
        return this;
    }

    public CanonicalEncoder add(String value) {
        return add(value.getBytes(StandardCharsets.UTF_8));
    }

    public CanonicalEncoder add(UUID value) {
        return add(Bytes.uuid(value));
    }

    public CanonicalEncoder add(long value) {
        byte[] encoded = new byte[8];
        for (int i = 7; i >= 0; i--) {
            encoded[i] = (byte) value;
            value >>>= 8;
        }
        return add(encoded);
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    private void writeInt(int value) {
        out.write(value >>> 24);
        out.write(value >>> 16);
        out.write(value >>> 8);
        out.write(value);
    }
}
