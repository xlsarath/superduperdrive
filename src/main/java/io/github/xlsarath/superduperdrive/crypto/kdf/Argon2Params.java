package io.github.xlsarath.superduperdrive.crypto.kdf;

/**
 * Argon2id cost parameters. Stored next to every password-wrapped key bundle so the cost can
 * be raised for new bundles without breaking old ones.
 *
 * @param memoryKib   memory cost in KiB
 * @param iterations  number of passes over memory
 * @param parallelism number of lanes
 */
public record Argon2Params(int memoryKib, int iterations, int parallelism) {

    /** Floors below which we refuse to derive keys at all, even from a tampered database row. */
    public static final int MIN_MEMORY_KIB = 8 * 1024;
    public static final int MIN_ITERATIONS = 1;

    public Argon2Params {
        if (parallelism < 1 || parallelism > 16) {
            throw new IllegalArgumentException("Argon2 parallelism must be between 1 and 16");
        }
        if (iterations < MIN_ITERATIONS || iterations > 64) {
            throw new IllegalArgumentException("Argon2 iterations must be between 1 and 64");
        }
        if (memoryKib < MIN_MEMORY_KIB || memoryKib > 4 * 1024 * 1024) {
            throw new IllegalArgumentException("Argon2 memory must be between 8 MiB and 4 GiB");
        }
        if (memoryKib < 8 * parallelism) {
            throw new IllegalArgumentException("Argon2 memory must be at least 8 KiB per lane");
        }
    }

    /** RFC 9106 section 4, second recommended option (64 MiB, t=3), with a single lane. */
    public static Argon2Params rfc9106LowMemory() {
        return new Argon2Params(64 * 1024, 3, 1);
    }

    public String describe() {
        return "m=" + memoryKib + "KiB,t=" + iterations + ",p=" + parallelism;
    }
}
