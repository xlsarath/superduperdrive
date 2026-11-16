package io.github.xlsarath.superduperdrive.service;

import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;

import java.util.UUID;

/** The item does not exist or belongs to someone else (deliberately indistinguishable). */
public class ItemNotFoundException extends RuntimeException {

    public ItemNotFoundException(ItemKind kind, UUID id) {
        super(kind.code() + " " + id + " not found");
    }
}
