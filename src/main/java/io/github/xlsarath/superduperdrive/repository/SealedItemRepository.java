package io.github.xlsarath.superduperdrive.repository;

import io.github.xlsarath.superduperdrive.domain.SealedItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Derived queries shared by every encrypted item type. Every lookup is scoped by owner, so an
 * id belonging to another user behaves exactly like an id that does not exist.
 */
@NoRepositoryBean
public interface SealedItemRepository<T extends SealedItem> extends JpaRepository<T, UUID> {

    List<T> findAllByOwnerIdOrderByCreatedAtAsc(UUID ownerId);

    Optional<T> findByIdAndOwnerId(UUID id, UUID ownerId);

    /** Items that were sealed with any suite other than {@code suiteId}: the migration work list. */
    List<T> findAllByOwnerIdAndSuiteIdNot(UUID ownerId, String suiteId);

    long countByOwnerId(UUID ownerId);
}
