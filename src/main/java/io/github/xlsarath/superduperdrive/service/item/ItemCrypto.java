package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.suite.CryptoSuiteRegistry;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemCipher;
import io.github.xlsarath.superduperdrive.crypto.suite.SealedDataKey;
import io.github.xlsarath.superduperdrive.crypto.suite.UnsupportedSuiteException;
import io.github.xlsarath.superduperdrive.domain.SealedItem;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * The single place where item services meet the suite registry: new items are sealed with the
 * current suite, existing items are opened with the suite recorded on the row.
 */
@Component
public class ItemCrypto {

    private final CryptoSuiteRegistry registry;

    public ItemCrypto(CryptoSuiteRegistry registry) {
        this.registry = registry;
    }

    public String currentSuiteId() {
        return registry.current().id();
    }

    public CryptoSuiteRegistry registry() {
        return registry;
    }

    /** Fresh DEK for {@code item}, wrapped to the active user's (session-derived) public key. */
    public SealedDataKey newDataKey(SealedItem item, ActiveUser user) {
        requireOwner(item, user);
        return registry.current().newDataKey(item.context(), user.keyring().publicKeys().encryptionKey());
    }

    /** Opens the DEK of a sealed item with the active user's private key. */
    public ItemCipher open(SealedItem item, ActiveUser user) {
        requireOwner(item, user);
        var envelope = item.envelope().orElseThrow(() ->
                new UnsupportedSuiteException("item " + item.getId() + " has no envelope (suite " + item.getSuiteId() + ")"));
        return registry.envelopeSuite(item.getSuiteId())
                .openDataKey(item.context(), envelope, user.keyring().hybridPrivateKey());
    }

    static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    static String string(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    private static void requireOwner(SealedItem item, ActiveUser user) {
        if (!item.getOwnerId().equals(user.id())) {
            throw new IllegalArgumentException("item does not belong to the active user");
        }
    }
}
