package io.github.xlsarath.superduperdrive.service;

import java.util.Objects;
import java.util.UUID;

/** The signed-in user on whose behalf a service call runs, with their unlocked keys. */
public record ActiveUser(UUID id, String username, UnlockedKeyring keyring) {

    public ActiveUser {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(keyring, "keyring");
        if (!id.equals(keyring.userId())) {
            throw new IllegalArgumentException("keyring belongs to a different user");
        }
    }
}
