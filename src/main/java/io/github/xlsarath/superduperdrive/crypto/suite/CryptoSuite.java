package io.github.xlsarath.superduperdrive.crypto.suite;

/** Common contract of every registered algorithm suite (strategy pattern). */
public interface CryptoSuite {

    SuiteDescriptor descriptor();

    default String id() {
        return descriptor().id();
    }
}
