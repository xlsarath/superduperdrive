package io.github.xlsarath.superduperdrive.crypto.suite;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Registry of every algorithm suite the application can read, and the one it writes with.
 *
 * <p>Adding a suite (for example ML-KEM-1024, or a standardised X-Wing) means registering a
 * new {@link EnvelopeSuite} and pointing {@code sdd.crypto.current-suite} at it; existing
 * items keep decrypting under their recorded suite id and are re-keyed by the migration
 * service on their owner's next login.
 */
public final class CryptoSuiteRegistry {

    private final Map<String, CryptoSuite> suites;
    private final EnvelopeSuite current;

    public CryptoSuiteRegistry(List<? extends CryptoSuite> suites, String currentSuiteId) {
        this.suites = suites.stream().collect(Collectors.toMap(CryptoSuite::id, Function.identity(),
                (a, b) -> {
                    throw new IllegalStateException("duplicate suite id " + a.id());
                }, LinkedHashMap::new));
        CryptoSuite configured = this.suites.get(currentSuiteId);
        if (!(configured instanceof EnvelopeSuite envelopeSuite)) {
            throw new IllegalStateException("current suite " + currentSuiteId + " is not a registered envelope suite");
        }
        this.current = envelopeSuite;
    }

    /** The suite used for all new encryptions. */
    public EnvelopeSuite current() {
        return current;
    }

    public boolean isCurrent(String suiteId) {
        return current.id().equals(suiteId);
    }

    /** Resolves a persisted suite id for decryption. */
    public EnvelopeSuite envelopeSuite(String suiteId) {
        CryptoSuite suite = suites.get(suiteId);
        if (suite instanceof EnvelopeSuite envelopeSuite) {
            return envelopeSuite;
        }
        throw new UnsupportedSuiteException("no envelope suite registered for id " + suiteId);
    }

    /** Resolves a suite of a specific (for example legacy) type. */
    public <T extends CryptoSuite> T require(String suiteId, Class<T> type) {
        CryptoSuite suite = suites.get(suiteId);
        if (type.isInstance(suite)) {
            return type.cast(suite);
        }
        throw new UnsupportedSuiteException("no " + type.getSimpleName() + " registered for id " + suiteId);
    }

    /** All suites with their effective status, current first. */
    public List<SuiteDescriptor> descriptors() {
        return suites.values().stream()
                .map(this::effectiveDescriptor)
                .sorted(Comparator.comparing(SuiteDescriptor::status).thenComparing(SuiteDescriptor::id))
                .toList();
    }

    public SuiteDescriptor descriptor(String suiteId) {
        CryptoSuite suite = suites.get(suiteId);
        if (suite == null) {
            throw new UnsupportedSuiteException("unknown suite id " + suiteId);
        }
        return effectiveDescriptor(suite);
    }

    private SuiteDescriptor effectiveDescriptor(CryptoSuite suite) {
        SuiteDescriptor descriptor = suite.descriptor();
        if (suite instanceof EnvelopeSuite) {
            return descriptor.withStatus(suite == current ? SuiteStatus.CURRENT : SuiteStatus.SUPPORTED);
        }
        return descriptor;
    }
}
