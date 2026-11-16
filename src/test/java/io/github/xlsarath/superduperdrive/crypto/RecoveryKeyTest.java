package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.keys.RecoveryKey;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RecoveryKeyTest {

    @Test
    void displayIsFourteenGroupsOfFourBase32Characters() {
        try (RecoveryKey key = RecoveryKey.generate(TestKeys.RANDOM)) {
            assertThat(key.display()).matches("([A-Z2-7]{4}-){13}[A-Z2-7]{4}");
        }
    }

    @Test
    void parsingIsLenientAboutCaseSpacesAndDashes() {
        try (RecoveryKey key = RecoveryKey.generate(TestKeys.RANDOM)) {
            String sloppy = "  " + key.display().toLowerCase(Locale.ROOT).replace('-', ' ') + "\n";
            try (RecoveryKey parsed = RecoveryKey.parse(sloppy)) {
                assertThat(parsed.keyBytes()).isEqualTo(key.keyBytes());
            }
        }
    }

    @Test
    void checksumCatchesTypos() {
        try (RecoveryKey key = RecoveryKey.generate(TestKeys.RANDOM)) {
            char[] chars = key.display().toCharArray();
            chars[0] = chars[0] == 'A' ? 'B' : 'A';
            assertThatThrownBy(() -> RecoveryKey.parse(new String(chars)))
                    .isInstanceOf(RecoveryKey.InvalidRecoveryKeyException.class);
        }
    }

    @Test
    void rejectsMalformedInput() {
        for (String bad : new String[] {null, "", "too-short", "0000-1111-8888-9999-0000-1111-8888-9999-0000-1111-8888-9999-0000-1111"}) {
            assertThatThrownBy(() -> RecoveryKey.parse(bad)).isInstanceOf(RecoveryKey.InvalidRecoveryKeyException.class);
        }
    }

    @Test
    void toStringNeverLeaksTheKey() {
        try (RecoveryKey key = RecoveryKey.generate(TestKeys.RANDOM)) {
            assertThat(key.toString()).doesNotContain(key.display().substring(0, 4) + "-");
        }
    }
}
