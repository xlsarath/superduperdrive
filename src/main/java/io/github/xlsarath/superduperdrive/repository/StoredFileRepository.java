package io.github.xlsarath.superduperdrive.repository;

import io.github.xlsarath.superduperdrive.domain.StoredFile;

public interface StoredFileRepository extends SealedItemRepository<StoredFile> {

    boolean existsByOwnerIdAndNameTag(java.util.UUID ownerId, byte[] nameTag);

    boolean existsByBlobKey(String blobKey);
}
