package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.kdf.Argon2Params;
import io.github.xlsarath.superduperdrive.crypto.keys.KeyBundleProtector;
import io.github.xlsarath.superduperdrive.crypto.keys.KeyWrapMethod;
import io.github.xlsarath.superduperdrive.crypto.keys.RecoveryKey;
import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;
import io.github.xlsarath.superduperdrive.crypto.keys.WrappedKeyBundle;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyBundleProtectorTest {

    private static final Argon2Params FAST = new Argon2Params(8192, 1, 1);
    private final KeyBundleProtector protector = new KeyBundleProtector(TestKeys.RANDOM, FAST);
    private final UUID userId = UUID.randomUUID();

    @Test
    void passwordWrapRoundTrips() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            WrappedKeyBundle bundle = protector.wrapWithPassword(userId, "correct horse".toCharArray(), keys);
            assertThat(bundle.method()).isEqualTo(KeyWrapMethod.PASSWORD_ARGON2ID);
            assertThat(bundle.argon2()).isEqualTo(FAST);
            try (UserKeyMaterial unwrapped = protector.unwrapWithPassword(userId, "correct horse".toCharArray(), bundle)) {
                assertThat(unwrapped.publicKeys()).isEqualTo(keys.publicKeys());
            }
        }
    }

    @Test
    void wrongPasswordFails() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            WrappedKeyBundle bundle = protector.wrapWithPassword(userId, "correct horse".toCharArray(), keys);
            assertThatThrownBy(() -> protector.unwrapWithPassword(userId, "wrong horse".toCharArray(), bundle))
                    .isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void bundleIsBoundToTheUserAndItsParameters() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            WrappedKeyBundle bundle = protector.wrapWithPassword(userId, "pw-pw-pw-pw".toCharArray(), keys);
            assertThatThrownBy(() -> protector.unwrapWithPassword(UUID.randomUUID(), "pw-pw-pw-pw".toCharArray(), bundle))
                    .isInstanceOf(IntegrityException.class);

            WrappedKeyBundle downgraded = new WrappedKeyBundle(bundle.method(), bundle.salt(),
                    new Argon2Params(8192, 2, 1), bundle.nonce(), bundle.ciphertext());
            assertThatThrownBy(() -> protector.unwrapWithPassword(userId, "pw-pw-pw-pw".toCharArray(), downgraded))
                    .isInstanceOf(IntegrityException.class);

            byte[] ct = bundle.ciphertext();
            ct[10] ^= 1;
            WrappedKeyBundle tampered = new WrappedKeyBundle(bundle.method(), bundle.salt(), bundle.argon2(),
                    bundle.nonce(), ct);
            assertThatThrownBy(() -> protector.unwrapWithPassword(userId, "pw-pw-pw-pw".toCharArray(), tampered))
                    .isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void recoveryKeyWrapRoundTripsAndRejectsOtherKeys() {
        try (UserKeyMaterial keys = TestKeys.newKeys(); RecoveryKey recovery = RecoveryKey.generate(TestKeys.RANDOM);
             RecoveryKey other = RecoveryKey.generate(TestKeys.RANDOM)) {
            WrappedKeyBundle bundle = protector.wrapWithRecoveryKey(userId, recovery, keys);
            assertThat(bundle.argon2()).isNull();
            try (RecoveryKey parsed = RecoveryKey.parse(recovery.display());
                 UserKeyMaterial unwrapped = protector.unwrapWithRecoveryKey(userId, parsed, bundle)) {
                assertThat(unwrapped.publicKeys()).isEqualTo(keys.publicKeys());
            }
            assertThatThrownBy(() -> protector.unwrapWithRecoveryKey(userId, other, bundle))
                    .isInstanceOf(IntegrityException.class);
            assertThatThrownBy(() -> protector.unwrapWithPassword(userId, "x".toCharArray(), bundle))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void argon2ParametersHaveSafeFloors() {
        assertThatThrownBy(() -> new Argon2Params(1024, 1, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Argon2Params(65536, 0, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThat(Argon2Params.rfc9106LowMemory()).isEqualTo(new Argon2Params(65536, 3, 1));
    }
}
