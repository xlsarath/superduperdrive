package io.github.xlsarath.superduperdrive.security;

import io.github.xlsarath.superduperdrive.config.DriveProperties;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sliding-window limiter keyed by client address, for login and recovery attempts. Bounded:
 * the least recently seen clients are evicted once {@code maxTrackedClients} is reached, so the
 * table cannot be used to exhaust memory.
 */
@Component
public class ClientRateLimiter {

    private final int maxAttempts;
    private final Duration window;
    private final Clock clock;
    private final Map<String, Deque<Instant>> attempts;

    public ClientRateLimiter(DriveProperties properties, Clock clock) {
        DriveProperties.Login login = properties.login();
        this.maxAttempts = login.maxAttemptsPerIp();
        this.window = login.ipWindow();
        this.clock = clock;
        int capacity = login.maxTrackedClients();
        this.attempts = new LinkedHashMap<>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Deque<Instant>> eldest) {
                return size() > capacity;
            }
        };
    }

    /** Records an attempt; returns {@code false} if the client is over its limit. */
    public synchronized boolean tryAcquire(String client) {
        Instant now = clock.instant();
        Deque<Instant> recent = attempts.computeIfAbsent(client, key -> new ArrayDeque<>());
        Instant horizon = now.minus(window);
        while (!recent.isEmpty() && !recent.peekFirst().isAfter(horizon)) {
            recent.pollFirst();
        }
        if (recent.size() >= maxAttempts) {
            return false;
        }
        recent.addLast(now);
        return true;
    }

    synchronized void reset() {
        attempts.clear();
    }
}
