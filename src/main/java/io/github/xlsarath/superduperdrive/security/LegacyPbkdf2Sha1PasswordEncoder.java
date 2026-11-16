package io.github.xlsarath.superduperdrive.security;

import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Verifies password hashes written by the 2020 version of the application:
 * PBKDF2-HMAC-SHA1, 5000 iterations, 128-bit output, where the salt was the <em>Base64 text</em>
 * of 16 random bytes. Stored as {@code {legacy-pbkdf2-sha1}<base64 salt>$<base64 hash>}.
 *
 * <p>Verify-only: {@link #encode} refuses, and {@link #upgradeEncoding} always asks for an
 * upgrade so the delegating encoder replaces the hash with Argon2id at the next login.
 */
public final class LegacyPbkdf2Sha1PasswordEncoder implements PasswordEncoder {

    public static final String ID = "legacy-pbkdf2-sha1";
    private static final int ITERATIONS = 5000;
    private static final int KEY_BITS = 128;

    @Override
    public String encode(CharSequence rawPassword) {
        throw new UnsupportedOperationException("legacy hashes are verify-only");
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        int separator = encodedPassword.indexOf('$');
        if (separator <= 0 || separator == encodedPassword.length() - 1) {
            return false;
        }
        String salt = encodedPassword.substring(0, separator);
        byte[] expected;
        try {
            expected = Base64.getDecoder().decode(encodedPassword.substring(separator + 1));
        } catch (IllegalArgumentException e) {
            return false;
        }
        char[] password = rawPassword.toString().toCharArray();
        PBEKeySpec spec = new PBEKeySpec(password, salt.getBytes(StandardCharsets.US_ASCII), ITERATIONS, KEY_BITS);
        byte[] actual = null;
        try {
            actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();
            return Bytes.constantTimeEquals(expected, actual);
        } catch (GeneralSecurityException e) {
            return false;
        } finally {
            spec.clearPassword();
            Bytes.wipe(password);
            Bytes.wipe(actual);
        }
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        return true;
    }
}
