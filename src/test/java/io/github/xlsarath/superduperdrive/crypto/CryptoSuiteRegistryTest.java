package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.suite.CryptoSuiteRegistry;
import io.github.xlsarath.superduperdrive.crypto.suite.HybridAesGcmSuiteV1;
import io.github.xlsarath.superduperdrive.crypto.suite.LegacyAesEcbCredentialSuite;
import io.github.xlsarath.superduperdrive.crypto.suite.SuiteDescriptor;
import io.github.xlsarath.superduperdrive.crypto.suite.SuiteStatus;
import io.github.xlsarath.superduperdrive.crypto.suite.UnsupportedSuiteException;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CryptoSuiteRegistryTest {

    private final HybridAesGcmSuiteV1 hybrid = new HybridAesGcmSuiteV1(TestKeys.RANDOM, 65536);
    private final LegacyAesEcbCredentialSuite legacy = new LegacyAesEcbCredentialSuite();
    private final CryptoSuiteRegistry registry = new CryptoSuiteRegistry(List.of(legacy, hybrid), HybridAesGcmSuiteV1.ID);

    @Test
    void resolvesCurrentAndRecordedSuites() {
        assertThat(registry.current()).isSameAs(hybrid);
        assertThat(registry.isCurrent(HybridAesGcmSuiteV1.ID)).isTrue();
        assertThat(registry.envelopeSuite(HybridAesGcmSuiteV1.ID)).isSameAs(hybrid);
        assertThat(registry.require(LegacyAesEcbCredentialSuite.ID, LegacyAesEcbCredentialSuite.class)).isSameAs(legacy);
    }

    @Test
    void legacySuiteIsDecryptOnlyAndNeverAnEnvelopeSuite() {
        assertThatThrownBy(() -> registry.envelopeSuite(LegacyAesEcbCredentialSuite.ID))
                .isInstanceOf(UnsupportedSuiteException.class);
        assertThat(registry.descriptor(LegacyAesEcbCredentialSuite.ID).status()).isEqualTo(SuiteStatus.LEGACY_DECRYPT_ONLY);
        assertThat(registry.descriptor(LegacyAesEcbCredentialSuite.ID).quantumSafe()).isFalse();
    }

    @Test
    void unknownSuitesAreRejected() {
        assertThatThrownBy(() -> registry.envelopeSuite("ROT13-v0")).isInstanceOf(UnsupportedSuiteException.class);
        assertThatThrownBy(() -> registry.descriptor("ROT13-v0")).isInstanceOf(UnsupportedSuiteException.class);
    }

    @Test
    void descriptorsListCurrentFirst() {
        List<SuiteDescriptor> descriptors = registry.descriptors();
        assertThat(descriptors).extracting(SuiteDescriptor::id)
                .containsExactly(HybridAesGcmSuiteV1.ID, LegacyAesEcbCredentialSuite.ID);
        assertThat(descriptors.getFirst().status()).isEqualTo(SuiteStatus.CURRENT);
    }

    @Test
    void misconfigurationFailsFast() {
        assertThatThrownBy(() -> new CryptoSuiteRegistry(List.of(hybrid), LegacyAesEcbCredentialSuite.ID))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new CryptoSuiteRegistry(List.of(hybrid, hybrid), HybridAesGcmSuiteV1.ID))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void legacySuiteDecryptsRowsWrittenByThe2020Application() {
        // Produced by the 2020 EncryptionService: key = bytes of the Base64 text, AES/ECB/PKCS5Padding.
        byte[] plaintext = legacy.decrypt("HUQHSPSbVLk92JyMNQgCF/7zIYsyJpm8erP3jnK2P9E=", "kh1dzoGmM40lvT8+GnvE8Q==");
        assertThat(new String(plaintext, StandardCharsets.UTF_8)).isEqualTo("cobol-forever-1959");
        assertThatThrownBy(() -> legacy.decrypt("HUQHSPSbVLk92JyMNQgCF/7zIYsyJpm8erP3jnK2P9E=", "4Xr67JEHgWzx1ZZpddc5ww=="))
                .isInstanceOf(IntegrityException.class);
        assertThatThrownBy(() -> legacy.decrypt("not base64!", "kh1dzoGmM40lvT8+GnvE8Q=="))
                .isInstanceOf(IntegrityException.class);
    }
}
