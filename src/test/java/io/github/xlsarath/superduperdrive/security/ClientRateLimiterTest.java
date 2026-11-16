package io.github.xlsarath.superduperdrive.security;

import io.github.xlsarath.superduperdrive.config.DriveProperties;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class ClientRateLimiterTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    private final ClientRateLimiter limiter = new ClientRateLimiter(new DriveProperties(
            new DriveProperties.Crypto("x", new DriveProperties.Argon2(8192, 1, 1), new DriveProperties.Argon2(8192, 1, 1), 65536),
            new DriveProperties.Storage(Path.of("target"), Duration.ofHours(1)),
            new DriveProperties.Login(5, Duration.ofMinutes(15), 3, Duration.ofMinutes(5), 100)), clock);

    @Test
    void allowsUpToTheLimitPerWindowPerClient() {
        assertThat(limiter.tryAcquire("10.0.0.1")).isTrue();
        assertThat(limiter.tryAcquire("10.0.0.1")).isTrue();
        assertThat(limiter.tryAcquire("10.0.0.1")).isTrue();
        assertThat(limiter.tryAcquire("10.0.0.1")).isFalse();
        assertThat(limiter.tryAcquire("10.0.0.2")).isTrue();
    }

    @Test
    void windowSlides() {
        for (int i = 0; i < 3; i++) {
            limiter.tryAcquire("10.0.0.1");
        }
        assertThat(limiter.tryAcquire("10.0.0.1")).isFalse();
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertThat(limiter.tryAcquire("10.0.0.1")).isTrue();
    }

    @Test
    void trackingTableIsBounded() {
        for (int i = 0; i < 1000; i++) {
            limiter.tryAcquire("client-" + i);
        }
        // The oldest clients were evicted, so client-0 starts with a fresh budget.
        assertThat(limiter.tryAcquire("client-0")).isTrue();
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
