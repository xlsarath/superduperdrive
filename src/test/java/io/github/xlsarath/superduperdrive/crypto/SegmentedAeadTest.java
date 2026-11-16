package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.stream.SegmentedAead;
import io.github.xlsarath.superduperdrive.crypto.stream.SegmentedAeadInputStream;
import io.github.xlsarath.superduperdrive.crypto.stream.SegmentedAeadOutputStream;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SegmentedAeadTest {

    private static final int SEGMENT = 4096;
    private static final int HEADER = 16;
    private static final int TAG = 16;
    private final byte[] key = random(32);
    private final byte[] aad = "item-aad".getBytes();

    @ParameterizedTest
    @ValueSource(ints = {0, 1, SEGMENT - 1, SEGMENT, SEGMENT + 1, 3 * SEGMENT, 3 * SEGMENT + 17})
    void roundTripsAllBoundarySizes(int size) throws IOException {
        byte[] plaintext = random(size);
        byte[] ciphertext = encrypt(plaintext);
        assertThat(ciphertext).hasSize((int) SegmentedAead.ciphertextLength(size, SEGMENT));
        assertThat(decrypt(ciphertext, aad)).isEqualTo(plaintext);
    }

    @Test
    void readsByteByByte() throws IOException {
        byte[] plaintext = random(SEGMENT + 5);
        try (InputStream in = new SegmentedAeadInputStream(new ByteArrayInputStream(encrypt(plaintext)), key, aad)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) >= 0) {
                out.write(b);
            }
            assertThat(out.toByteArray()).isEqualTo(plaintext);
        }
    }

    @Test
    void detectsBitFlipsAnywhere() throws IOException {
        byte[] ciphertext = encrypt(random(2 * SEGMENT + 10));
        for (int position : new int[] {0, 6, HEADER + 3, HEADER + SEGMENT + TAG + 1, ciphertext.length - 1}) {
            byte[] tampered = ciphertext.clone();
            tampered[position] ^= 0x01;
            assertThatThrownBy(() -> decrypt(tampered, aad)).isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void detectsTruncationAtASegmentBoundary() throws IOException {
        byte[] ciphertext = encrypt(random(3 * SEGMENT));
        byte[] truncated = Arrays.copyOf(ciphertext, HEADER + 2 * (SEGMENT + TAG));
        assertThatThrownBy(() -> decrypt(truncated, aad)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void detectsTruncationInsideASegmentAndOfTheHeader() throws IOException {
        byte[] ciphertext = encrypt(random(SEGMENT + 100));
        assertThatThrownBy(() -> decrypt(Arrays.copyOf(ciphertext, ciphertext.length - 1), aad))
                .isInstanceOf(IntegrityException.class);
        assertThatThrownBy(() -> decrypt(Arrays.copyOf(ciphertext, 10), aad)).isInstanceOf(IntegrityException.class);
        assertThatThrownBy(() -> decrypt(Arrays.copyOf(ciphertext, HEADER + 5), aad))
                .isInstanceOf(IntegrityException.class);
    }

    @Test
    void detectsAppendedData() throws IOException {
        byte[] ciphertext = encrypt(random(100));
        byte[] extended = Arrays.copyOf(ciphertext, ciphertext.length + 1);
        assertThatThrownBy(() -> decrypt(extended, aad)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void detectsReorderedSegments() throws IOException {
        byte[] ciphertext = encrypt(random(3 * SEGMENT));
        int len = SEGMENT + TAG;
        byte[] swapped = ciphertext.clone();
        System.arraycopy(ciphertext, HEADER, swapped, HEADER + len, len);
        System.arraycopy(ciphertext, HEADER + len, swapped, HEADER, len);
        assertThatThrownBy(() -> decrypt(swapped, aad)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void wrongKeyOrAadFails() throws IOException {
        byte[] ciphertext = encrypt(random(50));
        assertThatThrownBy(() -> decrypt(ciphertext, "other-item".getBytes())).isInstanceOf(IntegrityException.class);
        byte[] otherKey = random(32);
        assertThatThrownBy(() -> {
            try (InputStream in = new SegmentedAeadInputStream(new ByteArrayInputStream(ciphertext), otherKey, aad)) {
                in.readAllBytes();
            }
        }).isInstanceOf(IntegrityException.class);
    }

    @Test
    void rejectsOutOfRangeSegmentSizes() {
        assertThatThrownBy(() -> new SegmentedAeadOutputStream(new ByteArrayOutputStream(), key, aad, 100,
                TestKeys.RANDOM)).isInstanceOf(IllegalArgumentException.class);
    }

    private byte[] encrypt(byte[] plaintext) throws IOException {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (SegmentedAeadOutputStream out = new SegmentedAeadOutputStream(sink, key, aad, SEGMENT, TestKeys.RANDOM)) {
            // Uneven writes exercise the buffering.
            int offset = 0;
            int step = 1;
            while (offset < plaintext.length) {
                int n = Math.min(step, plaintext.length - offset);
                out.write(plaintext, offset, n);
                offset += n;
                step = step * 3 + 1;
            }
        }
        return sink.toByteArray();
    }

    private byte[] decrypt(byte[] ciphertext, byte[] associatedData) throws IOException {
        try (InputStream in = new SegmentedAeadInputStream(new ByteArrayInputStream(ciphertext), key, associatedData)) {
            return in.readAllBytes();
        }
    }

    private static byte[] random(int n) {
        byte[] bytes = new byte[n];
        TestKeys.RANDOM.nextBytes(bytes);
        return bytes;
    }
}
