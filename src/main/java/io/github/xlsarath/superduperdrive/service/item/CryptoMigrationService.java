package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.ItemNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Crypto agility in practice: brings every item of a user onto the current suite.
 *
 * <p>Runs right after login, because that is the only time the server can decrypt a user's
 * data. Each item is re-keyed in its own transaction, so one damaged item never blocks the
 * rest; failures are logged and retried at the next login.
 */
@Service
public class CryptoMigrationService {

    private static final Logger log = LoggerFactory.getLogger(CryptoMigrationService.class);

    private final Map<ItemKind, SealedItemHandler> handlers = new EnumMap<>(ItemKind.class);

    public CryptoMigrationService(List<SealedItemHandler> handlers) {
        handlers.forEach(handler -> {
            if (this.handlers.put(handler.kind(), handler) != null) {
                throw new IllegalStateException("duplicate handler for " + handler.kind());
            }
        });
    }

    /** Result of a migration run. */
    public record MigrationReport(int migrated, int failed) {
    }

    public MigrationReport migrateOutdatedItems(ActiveUser user) {
        int migrated = 0;
        int failed = 0;
        for (SealedItemHandler handler : handlers.values()) {
            for (UUID id : handler.outdatedItemIds(user)) {
                try {
                    handler.rekey(user, id);
                    migrated++;
                } catch (RuntimeException e) {
                    failed++;
                    log.error("Migration of {} {} for user {} failed; will retry at next login", handler.kind().code(),
                            id, user.id(), e);
                }
            }
        }
        if (migrated > 0 || failed > 0) {
            log.info("Crypto migration for user {}: {} item(s) migrated, {} failed", user.id(), migrated, failed);
        }
        return new MigrationReport(migrated, failed);
    }

    /** Re-keys one item on request (Security page). */
    public void rekey(ActiveUser user, ItemKind kind, UUID id) {
        SealedItemHandler handler = handlers.get(kind);
        if (handler == null) {
            throw new ItemNotFoundException(kind, id);
        }
        handler.rekey(user, id);
    }

    Map<ItemKind, SealedItemHandler> handlers() {
        return handlers;
    }
}
