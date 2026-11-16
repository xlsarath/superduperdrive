package io.github.xlsarath.superduperdrive.crypto.kdf;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id (RFC 9106, version 0x13) via Bouncy Castle's {@link Argon2BytesGenerator}.
 *
 * <p>Passwords are passed as {@code char[]} and converted to UTF-8 inside Bouncy Castle, so
 * callers can wipe their copy afterwards.
 */
public final class Argon2idKdf {

    public static final int MIN_SALT_BYTES = 16;

    private Argon2idKdf() {
    }

    public static byte[] derive(char[] password, byte[] salt, Argon2Params params, byte[] associatedData,
                                int outputBytes) {
        if (salt.length < MIN_SALT_BYTES) {
            throw new IllegalArgumentException("Argon2 salt must be at least 16 bytes");
        }
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(params.memoryKib())
                .withIterations(params.iterations())
                .withParallelism(params.parallelism())
                .withAdditional(associatedData);
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        byte[] out = new byte[outputBytes];
        generator.generateBytes(password, out);
        builder.clear();
        return out;
    }
}
