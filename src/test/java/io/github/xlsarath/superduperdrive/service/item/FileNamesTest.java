package io.github.xlsarath.superduperdrive.service.item;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FileNamesTest {

    @Test
    void keepsOnlyTheLastPathSegmentAndStripsControlCharacters() {
        assertThat(FileNames.sanitize("C:\\Users\\someone\\report.pdf")).isEqualTo("report.pdf");
        assertThat(FileNames.sanitize("../../etc/passwd")).isEqualTo("passwd");
        assertThat(FileNames.sanitize("  a\u0000b\u202Ec.txt ")).isEqualTo("abc.txt");
        assertThat(FileNames.sanitize("cafe\u0301.txt")).isEqualTo("caf\u00e9.txt");
    }

    @Test
    void rejectsUnusableNames() {
        for (String bad : new String[] {null, "", "   ", "..", "dir/", "\u0000", "x".repeat(256)}) {
            assertThatThrownBy(() -> FileNames.sanitize(bad)).isInstanceOf(InvalidUploadException.class);
        }
    }

    @Test
    void normalisesMediaTypes() {
        assertThat(FileNames.mediaType("text/plain; charset=UTF-8")).isEqualTo("text/plain");
        assertThat(FileNames.mediaType(null)).isEqualTo("application/octet-stream");
        assertThat(FileNames.mediaType("*/*")).isEqualTo("application/octet-stream");
        assertThat(FileNames.mediaType("garbage")).isEqualTo("application/octet-stream");
    }
}
