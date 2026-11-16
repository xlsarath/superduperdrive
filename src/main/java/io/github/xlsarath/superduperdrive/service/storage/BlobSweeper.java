package io.github.xlsarath.superduperdrive.service.storage;

import io.github.xlsarath.superduperdrive.config.DriveProperties;
import io.github.xlsarath.superduperdrive.repository.StoredFileRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;

/** Periodically removes abandoned pending writes and blobs no row references any more. */
@Component
public class BlobSweeper {

    private static final Logger log = LoggerFactory.getLogger(BlobSweeper.class);

    private final BlobStore blobStore;
    private final StoredFileRepository files;
    private final DriveProperties.Storage settings;

    public BlobSweeper(BlobStore blobStore, StoredFileRepository files, DriveProperties properties) {
        this.blobStore = blobStore;
        this.files = files;
        this.settings = properties.storage();
    }

    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "PT1H")
    public void sweep() {
        try {
            int removed = blobStore.sweep(settings.orphanGracePeriod(), files::existsByBlobKey);
            if (removed > 0) {
                log.info("Blob sweep removed {} orphaned blobs", removed);
            }
        } catch (IOException | RuntimeException e) {
            log.warn("Blob sweep failed", e);
        }
    }
}
