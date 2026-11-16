package io.github.xlsarath.superduperdrive.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;


import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordEncodingTest {

    /** Hash produced by the 2020 HashService for the fake password "grace-hopper-1906". */
    private static final String LEGACY = "{legacy-pbkdf2-sha1}3JtJsoXJ9Q94vScIO8l2Gw==$0f0aJ9fyQzEQU4ORvcxztg==";

    private final PasswordEncoder encoder = PasswordEncoders.delegating(8192, 1, 1);

    @Test
    void newHashesUseArgon2id() {
        String hash = encoder.encode("ada-lovelace-1815");
        assertThat(hash).startsWith("{argon2}$argon2id$v=19$");
        assertThat(encoder.matches("ada-lovelace-1815", hash)).isTrue();
        assertThat(encoder.matches("ada-lovelace-1816", hash)).isFalse();
        assertThat(encoder.upgradeEncoding(hash)).isFalse();
    }

    @Test
    void legacyHashesVerifyAndAskForAnUpgrade() {
        assertThat(encoder.matches("grace-hopper-1906", LEGACY)).isTrue();
        assertThat(encoder.matches("grace-hopper-1907", LEGACY)).isFalse();
        assertThat(encoder.upgradeEncoding(LEGACY)).isTrue();
    }

    @Test
    void legacyEncoderIsVerifyOnlyAndRobustToGarbage() {
        LegacyPbkdf2Sha1PasswordEncoder legacy = new LegacyPbkdf2Sha1PasswordEncoder();
        assertThatThrownBy(() -> legacy.encode("x")).isInstanceOf(UnsupportedOperationException.class);
        assertThat(legacy.matches("x", "no-separator")).isFalse();
        assertThat(legacy.matches("x", "salt$***")).isFalse();
        assertThat(legacy.matches("x", "$abc")).isFalse();
        assertThat(legacy.matches(null, "a$b")).isFalse();
    }
}
