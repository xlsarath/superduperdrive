package io.github.xlsarath.superduperdrive.support;

import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;

import java.security.SecureRandom;

/** Shared fixtures for crypto unit tests. */
public final class TestKeys {

    public static final SecureRandom RANDOM = new SecureRandom();

    private TestKeys() {
    }

    public static UserKeyMaterial newKeys() {
        return UserKeyMaterial.generate(RANDOM);
    }
}
