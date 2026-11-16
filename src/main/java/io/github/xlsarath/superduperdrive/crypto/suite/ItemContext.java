package io.github.xlsarath.superduperdrive.crypto.suite;

import java.util.Objects;
import java.util.UUID;

/**
 * Identity of the item being protected. Bound into the KEM combiner and every AEAD call, so a
 * ciphertext copied onto another item, another owner or another kind fails to decrypt.
 */
public record ItemContext(ItemKind kind, UUID itemId, UUID ownerId) {

    public ItemContext {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(itemId, "itemId");
        Objects.requireNonNull(ownerId, "ownerId");
    }
}
