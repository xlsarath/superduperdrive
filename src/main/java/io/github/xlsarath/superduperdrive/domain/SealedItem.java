package io.github.xlsarath.superduperdrive.domain;

import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemContext;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Version;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Columns shared by every encrypted item: identity, owner, the suite that sealed it, its key
 * envelope and the migration trail.
 *
 * <p>The id is assigned by the application before encryption because it is part of the
 * associated data; a ciphertext can only be opened under the id it was sealed for.
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class SealedItem {

    @Id
    private UUID id;

    @Column(name = "owner_id", nullable = false, updatable = false)
    private UUID ownerId;

    @Column(name = "suite_id", nullable = false, length = 64)
    private String suiteId;

    @Embedded
    private EnvelopeColumns envelope;

    @Column(name = "sealed_at")
    private Instant sealedAt;

    @Column(name = "migrated_from_suite", length = 64)
    private String migratedFromSuite;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    private Long version;

    protected SealedItem() {
    }

    protected SealedItem(UUID id, UUID ownerId, String suiteId) {
        this.id = id;
        this.ownerId = ownerId;
        this.suiteId = suiteId;
    }

    /** Used by factories that create rows imported from older schemas. */
    protected final void setIdentity(UUID id, UUID ownerId, String suiteId) {
        this.id = id;
        this.ownerId = ownerId;
        this.suiteId = suiteId;
    }

    public abstract ItemKind kind();

    public ItemContext context() {
        return new ItemContext(kind(), id, ownerId);
    }

    /** Records a (re-)seal under {@code newSuiteId}; remembers the previous suite if it changed. */
    protected void applySeal(String newSuiteId, Envelope newEnvelope, Instant now) {
        if (this.suiteId != null && !this.suiteId.equals(newSuiteId)) {
            this.migratedFromSuite = this.suiteId;
        }
        this.suiteId = newSuiteId;
        this.envelope = EnvelopeColumns.of(newEnvelope);
        this.sealedAt = now;
    }

    public Optional<Envelope> envelope() {
        return envelope != null && envelope.isPresent() ? Optional.of(envelope.toEnvelope()) : Optional.empty();
    }

    public UUID getId() {
        return id;
    }

    public UUID getOwnerId() {
        return ownerId;
    }

    public String getSuiteId() {
        return suiteId;
    }

    public Instant getSealedAt() {
        return sealedAt;
    }

    public Optional<String> getMigratedFromSuite() {
        return Optional.ofNullable(migratedFromSuite);
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Long getVersion() {
        return version;
    }
}
