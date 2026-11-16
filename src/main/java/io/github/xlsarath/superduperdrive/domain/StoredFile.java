package io.github.xlsarath.superduperdrive.domain;

import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Metadata of an uploaded file. The encrypted content lives in the blob store under
 * {@link #getBlobKey()}; name, media type and plaintext digest are encrypted fields; the
 * ML-DSA-65 signature covers the manifest built from them.
 */
@Entity
@Table(name = "stored_file")
public class StoredFile extends SealedItem {

    public static final String FIELD_NAME = "name";
    public static final String FIELD_CONTENT_TYPE = "contentType";
    public static final String FIELD_DIGEST = "sha3_256";

    @Column(name = "name_ciphertext", nullable = false)
    private byte[] nameCiphertext;

    @Column(name = "content_type_ciphertext", nullable = false)
    private byte[] contentTypeCiphertext;

    @Column(name = "digest_ciphertext", nullable = false)
    private byte[] digestCiphertext;

    @Column(name = "name_tag", nullable = false)
    private byte[] nameTag;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "blob_key", nullable = false, length = 64)
    private String blobKey;

    @Column(name = "signature")
    private byte[] signature;

    @Column(name = "signature_algorithm", length = 32)
    private String signatureAlgorithm;

    @Column(name = "signer_key_fingerprint", length = 64)
    private String signerKeyFingerprint;

    @Column(name = "uploaded_at", nullable = false, updatable = false)
    private Instant uploadedAt;

    protected StoredFile() {
    }

    public StoredFile(UUID id, UUID ownerId, byte[] nameTag, Instant uploadedAt) {
        super(id, ownerId, null);
        this.nameTag = nameTag.clone();
        this.uploadedAt = uploadedAt.truncatedTo(ChronoUnit.MILLIS);
    }

    @Override
    public ItemKind kind() {
        return ItemKind.FILE;
    }

    public void seal(String suiteId, Envelope envelope, String blobKey, long sizeBytes, byte[] nameCiphertext,
                     byte[] contentTypeCiphertext, byte[] digestCiphertext, Instant now) {
        if (sizeBytes < 0) {
            throw new IllegalArgumentException("size must not be negative");
        }
        applySeal(suiteId, envelope, now);
        this.blobKey = blobKey;
        this.sizeBytes = sizeBytes;
        this.nameCiphertext = nameCiphertext.clone();
        this.contentTypeCiphertext = contentTypeCiphertext.clone();
        this.digestCiphertext = digestCiphertext.clone();
    }

    public void sign(String algorithm, String signerFingerprint, byte[] signatureBytes) {
        this.signatureAlgorithm = algorithm;
        this.signerKeyFingerprint = signerFingerprint;
        this.signature = signatureBytes.clone();
    }

    public boolean isSigned() {
        return signature != null;
    }

    public byte[] getNameCiphertext() {
        return nameCiphertext.clone();
    }

    public byte[] getContentTypeCiphertext() {
        return contentTypeCiphertext.clone();
    }

    public byte[] getDigestCiphertext() {
        return digestCiphertext.clone();
    }

    public byte[] getNameTag() {
        return nameTag.clone();
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getBlobKey() {
        return blobKey;
    }

    public byte[] getSignature() {
        return signature == null ? null : signature.clone();
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getSignerKeyFingerprint() {
        return signerKeyFingerprint;
    }

    public Instant getUploadedAt() {
        return uploadedAt;
    }
}
