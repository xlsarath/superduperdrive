package io.github.xlsarath.superduperdrive.crypto.stream;

import io.github.xlsarath.superduperdrive.crypto.support.AesGcm;

import java.nio.charset.StandardCharsets;

/**
 * Constants and nonce layout for the segmented ("STREAM", Hoang-Reyhanitabar-Rogaway-Vizar 2015)
 * AES-256-GCM format used for file content:
 *
 * <pre>
 *   header  = "SDDS" | 0x01 | segment size (u32, big-endian) | nonce prefix (7 random bytes)   16 bytes
 *   segment = AES-256-GCM(k, nonce = prefix || counter (u32 BE) || last-flag (0x00 or 0x01),
 *                         aad = stream AAD || header, plaintext chunk)
 * </pre>
 *
 * <p>Every segment is authenticated before any of its plaintext is released. The counter
 * prevents reordering, the last-flag prevents truncation at a segment boundary and appending,
 * and the header is in every segment's AAD so it cannot be altered either.
 */
public final class SegmentedAead {

    static final byte[] MAGIC = "SDDS".getBytes(StandardCharsets.US_ASCII);
    static final byte VERSION = 0x01;
    static final int NONCE_PREFIX_BYTES = 7;
    static final int HEADER_BYTES = MAGIC.length + 1 + 4 + NONCE_PREFIX_BYTES;
    public static final int MIN_SEGMENT_BYTES = 4 * 1024;
    public static final int MAX_SEGMENT_BYTES = 4 * 1024 * 1024;
    public static final int DEFAULT_SEGMENT_BYTES = 64 * 1024;
    static final long MAX_SEGMENTS = 0xFFFF_FFFFL;

    private SegmentedAead() {
    }

    static byte[] nonce(byte[] prefix, long counter, boolean last) {
        byte[] nonce = new byte[AesGcm.NONCE_BYTES];
        System.arraycopy(prefix, 0, nonce, 0, NONCE_PREFIX_BYTES);
        nonce[7] = (byte) (counter >>> 24);
        nonce[8] = (byte) (counter >>> 16);
        nonce[9] = (byte) (counter >>> 8);
        nonce[10] = (byte) counter;
        nonce[11] = (byte) (last ? 1 : 0);
        return nonce;
    }

    static void checkSegmentSize(int segmentBytes) {
        if (segmentBytes < MIN_SEGMENT_BYTES || segmentBytes > MAX_SEGMENT_BYTES) {
            throw new IllegalArgumentException("segment size out of range");
        }
    }

    /** Ciphertext length for a given plaintext length; useful for sanity checks and tests. */
    public static long ciphertextLength(long plaintextLength, int segmentBytes) {
        // A final segment may be full; it is only empty when the whole input is empty.
        long segments = Math.max(1, (plaintextLength + segmentBytes - 1) / segmentBytes);
        return HEADER_BYTES + plaintextLength + segments * AesGcm.TAG_BYTES;
    }
}
