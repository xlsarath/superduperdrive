package io.github.xlsarath.superduperdrive.crypto.support;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;

/** Small, allocation-conscious helpers for byte arrays holding secrets. */
public final class Bytes {

    private static final HexFormat HEX = HexFormat.of();

    private Bytes() {
    }

    /** Constant-time equality; also constant-time with respect to where the first difference is. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return org.bouncycastle.util.Arrays.constantTimeAreEqual(a, b);
    }

    /** Overwrites every given array with zeros. Null-safe. */
    public static void wipe(byte[]... arrays) {
        for (byte[] array : arrays) {
            if (array != null) {
                Arrays.fill(array, (byte) 0);
            }
        }
    }

    /** Overwrites a char array (for example a password) with zeros. Null-safe. */
    public static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    public static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length = Math.addExact(length, part.length);
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    public static byte[] uuid(UUID id) {
        return ByteBuffer.allocate(16)
                .putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits())
                .array();
    }

    public static String hex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    public static byte[] requireLength(byte[] value, int expected, String what) {
        if (value == null || value.length != expected) {
            throw new IllegalArgumentException(what + " must be exactly " + expected + " bytes");
        }
        return value;
    }
}
