package io.github.xlsarath.superduperdrive.security;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

/**
 * Argon2id for all new hashes; PBKDF2-SHA1 hashes from the 2020 schema still verify and are
 * re-encoded with Argon2id on the next successful login (Spring Security's
 * {@code UserDetailsPasswordService} upgrade path).
 */
public final class PasswordEncoders {

    public static final String ARGON2_ID = "argon2";

    private PasswordEncoders() {
    }

    public static PasswordEncoder delegating(int memoryKib, int iterations, int parallelism) {
        Argon2PasswordEncoder argon2 = new Argon2PasswordEncoder(16, 32, parallelism, memoryKib, iterations);
        Map<String, PasswordEncoder> encoders = Map.of(
                ARGON2_ID, argon2,
                LegacyPbkdf2Sha1PasswordEncoder.ID, new LegacyPbkdf2Sha1PasswordEncoder());
        return new DelegatingPasswordEncoder(ARGON2_ID, encoders);
    }
}
