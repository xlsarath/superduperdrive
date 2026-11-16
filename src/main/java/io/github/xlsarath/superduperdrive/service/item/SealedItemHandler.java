package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.service.ActiveUser;

import java.util.List;
import java.util.UUID;

/**
 * Per-kind operations the crypto-agility machinery needs. Implemented by each item service and
 * discovered by {@link CryptoMigrationService} and {@link SecurityOverviewService}.
 */
public interface SealedItemHandler {

    ItemKind kind();

    /** Ids of the user's items not sealed with the current suite (including legacy rows). */
    List<UUID> outdatedItemIds(ActiveUser user);

    /** Re-encrypts one item under the current suite with a fresh DEK and a fresh encapsulation. */
    void rekey(ActiveUser user, UUID itemId);

    /** Security-page rows for all of the user's items of this kind. */
    List<SecurityItemView> describe(ActiveUser user);
}
