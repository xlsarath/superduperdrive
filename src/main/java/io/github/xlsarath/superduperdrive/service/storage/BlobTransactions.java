package io.github.xlsarath.superduperdrive.service.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.io.IOException;

/**
 * Keeps blob files consistent with database rows: a blob written for a row is deleted if the
 * transaction rolls back, and a blob released by a row is deleted only after the commit.
 * Anything missed (a crash between the two) is collected by {@link BlobSweeper}.
 */
@Component
public class BlobTransactions {

    private static final Logger log = LoggerFactory.getLogger(BlobTransactions.class);

    private final BlobStore blobStore;

    public BlobTransactions(BlobStore blobStore) {
        this.blobStore = blobStore;
    }

    public void deleteOnRollback(String key) {
        register(key, false);
    }

    public void deleteAfterCommit(String key) {
        register(key, true);
    }

    private void register(String key, boolean onCommit) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            throw new IllegalStateException("blob lifecycle changes require an active transaction");
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                boolean committed = status == STATUS_COMMITTED;
                if (committed == onCommit) {
                    deleteQuietly(key, committed ? "released after commit" : "orphaned by rollback");
                }
            }
        });
    }

    private void deleteQuietly(String key, String reason) {
        try {
            if (blobStore.delete(key)) {
                log.debug("Deleted blob {} ({})", key, reason);
            }
        } catch (IOException | RuntimeException e) {
            log.warn("Could not delete blob {} ({}); the sweeper will retry", key, reason, e);
        }
    }
}
