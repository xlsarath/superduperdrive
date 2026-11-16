package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.support.BlindIndex;
import io.github.xlsarath.superduperdrive.crypto.support.CanonicalEncoder;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BlindIndexTest {

    private final byte[] key = new byte[32];
    private final byte[] otherKey = new byte[32];

    {
        otherKey[0] = 1;
    }

    @Test
    void isCaseInsensitiveAndUnicodeNormalised() {
        assertThat(BlindIndex.tag(key, "file-name", "Report.TXT")).isEqualTo(BlindIndex.tag(key, "file-name", "report.txt"));
        // "é" precomposed vs "e" + combining acute accent
        assertThat(BlindIndex.tag(key, "file-name", "caf\u00e9")).isEqualTo(BlindIndex.tag(key, "file-name", "cafe\u0301"));
    }

    @Test
    void dependsOnKeyPurposeAndValue() {
        byte[] base = BlindIndex.tag(key, "file-name", "a.txt");
        assertThat(BlindIndex.tag(otherKey, "file-name", "a.txt")).isNotEqualTo(base);
        assertThat(BlindIndex.tag(key, "other", "a.txt")).isNotEqualTo(base);
        assertThat(BlindIndex.tag(key, "file-name", "b.txt")).isNotEqualTo(base);
        assertThat(base).hasSize(32);
    }

    @Test
    void canonicalEncodingIsInjective() {
        assertThat(CanonicalEncoder.create().add("ab").add("c").toByteArray())
                .isNotEqualTo(CanonicalEncoder.create().add("a").add("bc").toByteArray());
    }
}
