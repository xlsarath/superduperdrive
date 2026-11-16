package io.github.xlsarath.superduperdrive.config;

import io.github.xlsarath.superduperdrive.crypto.kdf.Argon2Params;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;
import java.time.Duration;

/** Application settings under the {@code sdd.*} prefix. */
@Validated
@ConfigurationProperties("sdd")
public record DriveProperties(@Valid @NotNull @DefaultValue Crypto crypto,
                              @Valid @NotNull @DefaultValue Storage storage,
                              @Valid @NotNull @DefaultValue Login login) {

    /**
     * @param currentSuite       suite id used for new encryptions
     * @param keyWrap            Argon2id cost for wrapping user private keys with the password
     * @param passwordHash       Argon2id cost for the login password hash
     * @param streamSegmentBytes plaintext bytes per STREAM segment for file content
     */
    public record Crypto(@NotBlank @DefaultValue("HYB-X25519-MLKEM768-AES256GCM-v1") String currentSuite,
                         @Valid @NotNull @DefaultValue({"65536", "3", "1"}) Argon2 keyWrap,
                         @Valid @NotNull @DefaultValue({"19456", "2", "1"}) Argon2 passwordHash,
                         @Min(4096) @DefaultValue("65536") int streamSegmentBytes) {
    }

    /** Argon2id cost, see RFC 9106 and the OWASP password storage cheat sheet. */
    public record Argon2(@Min(8192) int memoryKib, @Min(1) int iterations, @Min(1) int parallelism) {

        public Argon2Params toParams() {
            return new Argon2Params(memoryKib, iterations, parallelism);
        }
    }

    /**
     * @param blobDirectory       directory for encrypted file content
     * @param orphanGracePeriod   age after which unreferenced blobs are swept
     */
    public record Storage(@NotNull @DefaultValue("./data/blobs") Path blobDirectory,
                          @NotNull @DefaultValue("PT1H") Duration orphanGracePeriod) {
    }

    /**
     * @param maxFailures       consecutive failures before an account is locked
     * @param lockoutDuration   how long the lock lasts
     * @param maxAttemptsPerIp  login/recovery POSTs allowed per client address per window
     * @param ipWindow          sliding window for the per-address limit
     * @param maxTrackedClients bound on the in-memory limiter table
     */
    public record Login(@Min(1) @DefaultValue("5") int maxFailures,
                        @NotNull @DefaultValue("PT15M") Duration lockoutDuration,
                        @Min(1) @DefaultValue("20") int maxAttemptsPerIp,
                        @NotNull @DefaultValue("PT5M") Duration ipWindow,
                        @Min(100) @DefaultValue("10000") int maxTrackedClients) {
    }
}
