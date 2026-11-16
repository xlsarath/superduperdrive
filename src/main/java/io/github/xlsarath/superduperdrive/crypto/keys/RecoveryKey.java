package io.github.xlsarath.superduperdrive.crypto.keys;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.util.encoders.Base32;
import org.bouncycastle.util.encoders.DecoderException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * A 256-bit, user-held recovery secret that wraps a second copy of the user's private keys.
 *
 * <p>Display format: RFC 4648 Base32 of {@code key (32 bytes) || SHA3-256(label || key)[0..3)},
 * which is exactly 56 characters, shown as 14 groups of 4 (for example
 * {@code ABCD-EFGH-...}). The 24-bit checksum catches typos before any expensive work and
 * before a failed attempt counts towards the lockout. Parsing ignores case, spaces and hyphens.
 */
public final class RecoveryKey implements AutoCloseable {

    public static final int KEY_BYTES = 32;
    private static final int CHECKSUM_BYTES = 3;
    private static final int GROUP = 4;
    private static final byte[] CHECKSUM_LABEL = "SDD-RECOVERY-KEY-v1".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern SEPARATORS = Pattern.compile("[\\s-]+");
    private static final Pattern BASE32 = Pattern.compile("[A-Z2-7]{56}");

    private final byte[] key;

    private RecoveryKey(byte[] key) {
        this.key = key;
    }

    public static RecoveryKey generate(SecureRandom random) {
        byte[] key = new byte[KEY_BYTES];
        random.nextBytes(key);
        return new RecoveryKey(key);
    }

    /**
     * Parses user input.
     *
     * @throws InvalidRecoveryKeyException if the format or checksum is wrong
     */
    public static RecoveryKey parse(String input) {
        if (input == null) {
            throw new InvalidRecoveryKeyException();
        }
        String compact = SEPARATORS.matcher(input).replaceAll("").toUpperCase(Locale.ROOT);
        if (!BASE32.matcher(compact).matches()) {
            throw new InvalidRecoveryKeyException();
        }
        byte[] decoded;
        try {
            decoded = Base32.decode(compact);
        } catch (DecoderException e) {
            throw new InvalidRecoveryKeyException();
        }
        byte[] key = Arrays.copyOfRange(decoded, 0, KEY_BYTES);
        byte[] checksum = Arrays.copyOfRange(decoded, KEY_BYTES, KEY_BYTES + CHECKSUM_BYTES);
        boolean valid = Bytes.constantTimeEquals(checksum, checksum(key));
        Bytes.wipe(decoded);
        if (!valid) {
            Bytes.wipe(key);
            throw new InvalidRecoveryKeyException();
        }
        return new RecoveryKey(key);
    }

    /** Human-friendly representation, shown exactly once. */
    public String display() {
        byte[] payload = Bytes.concat(key, checksum(key));
        String base32 = Base32.toBase32String(payload);
        Bytes.wipe(payload);
        StringBuilder grouped = new StringBuilder(base32.length() + base32.length() / GROUP);
        for (int i = 0; i < base32.length(); i += GROUP) {
            if (i > 0) {
                grouped.append('-');
            }
            grouped.append(base32, i, i + GROUP);
        }
        return grouped.toString();
    }

    /** Returns a copy of the raw key; the caller must wipe it. */
    public byte[] keyBytes() {
        return key.clone();
    }

    @Override
    public void close() {
        Bytes.wipe(key);
    }

    private static byte[] checksum(byte[] key) {
        SHA3Digest sha3 = new SHA3Digest(256);
        sha3.update(CHECKSUM_LABEL, 0, CHECKSUM_LABEL.length);
        sha3.update(key, 0, key.length);
        byte[] digest = new byte[32];
        sha3.doFinal(digest, 0);
        return Arrays.copyOf(digest, CHECKSUM_BYTES);
    }

    @Override
    public String toString() {
        return "RecoveryKey[redacted]";
    }

    /** Thrown for malformed recovery keys. Never includes the input. */
    public static final class InvalidRecoveryKeyException extends CryptoException {
        public InvalidRecoveryKeyException() {
            super("recovery key is malformed or has a bad checksum");
        }
    }
}
