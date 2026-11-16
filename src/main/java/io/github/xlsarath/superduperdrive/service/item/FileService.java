package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import io.github.xlsarath.superduperdrive.crypto.keys.UserPublicKeys;
import io.github.xlsarath.superduperdrive.crypto.sign.FileManifest;
import io.github.xlsarath.superduperdrive.crypto.sign.ManifestSigner;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemCipher;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.crypto.suite.SealedDataKey;
import io.github.xlsarath.superduperdrive.crypto.support.BlindIndex;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import io.github.xlsarath.superduperdrive.domain.StoredFile;
import io.github.xlsarath.superduperdrive.repository.StoredFileRepository;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.ItemNotFoundException;
import io.github.xlsarath.superduperdrive.service.storage.BlobStore;
import io.github.xlsarath.superduperdrive.service.storage.BlobTransactions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static io.github.xlsarath.superduperdrive.service.item.ItemCrypto.string;
import static io.github.xlsarath.superduperdrive.service.item.ItemCrypto.utf8;

/**
 * Encrypted, signed file storage.
 *
 * <p>Upload streams the plaintext once: through SHA3-256 and into the segmented AES-GCM
 * encryptor, straight to a pending blob. The manifest (id, owner, name, type, size, digest,
 * time, signer) is then signed with the user's ML-DSA-65 key. Download verifies before it
 * sends anything: it decrypts the whole blob once to recompute the digest, checks it against
 * the signed manifest and checks the signature, and only then streams the plaintext.
 */
@Service
public class FileService implements SealedItemHandler {

    private static final Logger log = LoggerFactory.getLogger(FileService.class);
    private static final String NAME_TAG_PURPOSE = "file-name";

    private final StoredFileRepository files;
    private final ItemCrypto crypto;
    private final ManifestSigner signer;
    private final BlobStore blobStore;
    private final BlobTransactions blobTransactions;
    private final Clock clock;

    public FileService(StoredFileRepository files, ItemCrypto crypto, ManifestSigner signer, BlobStore blobStore,
                       BlobTransactions blobTransactions, Clock clock) {
        this.files = files;
        this.crypto = crypto;
        this.signer = signer;
        this.blobStore = blobStore;
        this.blobTransactions = blobTransactions;
        this.clock = clock;
    }

    @Override
    public ItemKind kind() {
        return ItemKind.FILE;
    }

    @Transactional(readOnly = true)
    public List<FileView> list(ActiveUser user) {
        return files.findAllByOwnerIdOrderByCreatedAtAsc(user.id()).stream().map(file -> view(user, file)).toList();
    }

    /**
     * Encrypts, signs and stores a file.
     *
     * @throws DuplicateFileNameException if the user already has a file with this name
     * @throws InvalidUploadException     if the name is unusable
     */
    @Transactional
    public UUID upload(ActiveUser user, UploadRequest request) throws IOException {
        String name = FileNames.sanitize(request.originalFilename());
        String contentType = FileNames.mediaType(request.contentType());
        byte[] nameTag = nameTag(user, name);
        if (files.existsByOwnerIdAndNameTag(user.id(), nameTag)) {
            throw new DuplicateFileNameException();
        }

        StoredFile file = new StoredFile(UUID.randomUUID(), user.id(), nameTag, clock.instant());
        try (BlobStore.PendingBlob blob = blobStore.begin();
             SealedDataKey key = crypto.newDataKey(file, user)) {
            MessageDigest sha3 = sha3();
            long size;
            try (InputStream plaintext = new DigestInputStream(request.content().getInputStream(), sha3);
                 OutputStream ciphertext = key.cipher().encryptingStream(blob.output())) {
                size = plaintext.transferTo(ciphertext);
            }
            byte[] digest = sha3.digest();
            file.seal(key.suiteId(), key.envelope(), blob.key(), size,
                    key.cipher().encryptField(StoredFile.FIELD_NAME, utf8(name)),
                    key.cipher().encryptField(StoredFile.FIELD_CONTENT_TYPE, utf8(contentType)),
                    key.cipher().encryptField(StoredFile.FIELD_DIGEST, digest),
                    clock.instant());
            sign(user, file, new FileManifest(file.getId(), user.id(), name, contentType, size, digest,
                    file.getUploadedAt(), user.keyring().publicKeys().signingKeyFingerprint()));
            blob.publish();
            blobTransactions.deleteOnRollback(blob.key());
            files.saveAndFlush(file);
            log.info("Stored file {} for user {}: {} bytes, suite {}, signed {}", file.getId(), user.id(), size,
                    file.getSuiteId(), FileManifest.ALGORITHM);
            return file.getId();
        } catch (DataIntegrityViolationException e) {
            log.info("Upload for user {} lost a race on the file name constraint", user.id());
            throw new DuplicateFileNameException();
        }
    }

    /**
     * Verifies content against the signed manifest and returns a streaming download.
     *
     * @throws IntegrityException if the content, the manifest or the signature does not verify
     */
    @Transactional(readOnly = true)
    public FileDownload download(ActiveUser user, UUID id) throws IOException {
        StoredFile file = find(user, id);
        ItemCipher cipher = crypto.open(file, user);
        try {
            FileManifest manifest = manifest(user, file, cipher);
            if (verify(user, file, manifest) != SignatureStatus.VERIFIED) {
                log.error("Refusing download of file {} for user {}: manifest signature invalid or missing", id, user.id());
                throw new IntegrityException("file signature does not verify");
            }
            byte[] actual = digestOfContent(file, cipher);
            if (!Bytes.constantTimeEquals(actual, manifest.sha3_256())) {
                log.error("Refusing download of file {} for user {}: content digest differs from the signed manifest",
                        id, user.id());
                throw new IntegrityException("file content does not match its signed digest");
            }
            log.info("Verified file {} for user {} (SHA3-256 and {}); streaming {} bytes", id, user.id(),
                    FileManifest.ALGORITHM, file.getSizeBytes());
            String blobKey = file.getBlobKey();
            return new FileDownload(manifest.fileName(), file.getSizeBytes(), out -> {
                try (cipher; InputStream in = cipher.decryptingStream(blobStore.open(blobKey))) {
                    in.transferTo(out);
                }
            });
        } catch (IOException | RuntimeException e) {
            cipher.close();
            throw e;
        }
    }

    /** The signed manifest for export. */
    @Transactional(readOnly = true)
    public SignedManifest signedManifest(ActiveUser user, UUID id) {
        StoredFile file = find(user, id);
        try (ItemCipher cipher = crypto.open(file, user)) {
            FileManifest manifest = manifest(user, file, cipher);
            boolean verified = verify(user, file, manifest) == SignatureStatus.VERIFIED;
            byte[] signature = file.getSignature();
            return new SignedManifest(manifest.toCanonicalMap(), FileManifest.ALGORITHM, FileManifest.CONTEXT,
                    signature == null ? null : Base64.getEncoder().encodeToString(signature),
                    Base64.getEncoder().encodeToString(user.keyring().publicKeys().mlDsa()), verified);
        }
    }

    @Transactional
    public void delete(ActiveUser user, UUID id) {
        StoredFile file = find(user, id);
        files.delete(file);
        blobTransactions.deleteAfterCommit(file.getBlobKey());
        log.info("Deleted file {} for user {}", id, user.id());
    }

    @Override
    @Transactional(readOnly = true)
    public List<UUID> outdatedItemIds(ActiveUser user) {
        return files.findAllByOwnerIdAndSuiteIdNot(user.id(), crypto.currentSuiteId()).stream()
                .map(StoredFile::getId).toList();
    }

    /**
     * Re-encrypts content and metadata under a fresh data key and the current suite. The
     * content digest is re-checked while copying, so re-keying never launders tampered data;
     * the signature stays valid because the manifest does not change.
     */
    @Override
    @Transactional
    public void rekey(ActiveUser user, UUID itemId) {
        StoredFile file = find(user, itemId);
        String previousSuite = file.getSuiteId();
        String previousBlob = file.getBlobKey();
        try (ItemCipher oldCipher = crypto.open(file, user)) {
            FileManifest manifest = manifest(user, file, oldCipher);
            if (verify(user, file, manifest) != SignatureStatus.VERIFIED) {
                throw new IntegrityException("refusing to re-key a file whose signature does not verify");
            }
            try (BlobStore.PendingBlob blob = blobStore.begin();
                 SealedDataKey key = crypto.newDataKey(file, user)) {
                MessageDigest sha3 = sha3();
                try (InputStream plaintext = new DigestInputStream(
                        oldCipher.decryptingStream(blobStore.open(previousBlob)), sha3);
                     OutputStream ciphertext = key.cipher().encryptingStream(blob.output())) {
                    plaintext.transferTo(ciphertext);
                }
                if (!Bytes.constantTimeEquals(sha3.digest(), manifest.sha3_256())) {
                    throw new IntegrityException("file content does not match its signed digest");
                }
                file.seal(key.suiteId(), key.envelope(), blob.key(), file.getSizeBytes(),
                        key.cipher().encryptField(StoredFile.FIELD_NAME, utf8(manifest.fileName())),
                        key.cipher().encryptField(StoredFile.FIELD_CONTENT_TYPE, utf8(manifest.contentType())),
                        key.cipher().encryptField(StoredFile.FIELD_DIGEST, manifest.sha3_256()),
                        clock.instant());
                blob.publish();
                blobTransactions.deleteOnRollback(blob.key());
                blobTransactions.deleteAfterCommit(previousBlob);
                files.saveAndFlush(file);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        log.info("Re-keyed file {} for user {}: {} -> {}", itemId, user.id(), previousSuite, file.getSuiteId());
    }

    @Override
    @Transactional(readOnly = true)
    public List<SecurityItemView> describe(ActiveUser user) {
        return files.findAllByOwnerIdOrderByCreatedAtAsc(user.id()).stream().map(file -> {
            FileView view = view(user, file);
            var suite = crypto.registry().descriptor(file.getSuiteId());
            return new SecurityItemView(ItemKind.FILE, file.getId(), view.name(), file.getSuiteId(),
                    crypto.registry().isCurrent(file.getSuiteId()), suite.quantumSafe(), file.getSealedAt(),
                    file.getMigratedFromSuite().orElse(null), view.signature(), view.readable());
        }).toList();
    }

    private FileView view(ActiveUser user, StoredFile file) {
        try (ItemCipher cipher = crypto.open(file, user)) {
            FileManifest manifest = manifest(user, file, cipher);
            SignatureStatus status = verify(user, file, manifest);
            if (status != SignatureStatus.VERIFIED) {
                log.warn("Signature of file {} for user {} is {}", file.getId(), user.id(), status);
            }
            return new FileView(file.getId(), manifest.fileName(), manifest.contentType(), file.getSizeBytes(),
                    file.getUploadedAt(), file.getSuiteId(), status, file.getSignatureAlgorithm(), true);
        } catch (CryptoException e) {
            log.warn("File {} of user {} failed to decrypt ({}): {}", file.getId(), user.id(), file.getSuiteId(),
                    e.getMessage());
            return new FileView(file.getId(), "Unreadable file", FileNames.DEFAULT_TYPE, file.getSizeBytes(),
                    file.getUploadedAt(), file.getSuiteId(), SignatureStatus.INVALID, file.getSignatureAlgorithm(),
                    false);
        }
    }

    /** Rebuilds the signed statement from the decrypted fields and the row. */
    private FileManifest manifest(ActiveUser user, StoredFile file, ItemCipher cipher) {
        return new FileManifest(file.getId(), file.getOwnerId(),
                string(cipher.decryptField(StoredFile.FIELD_NAME, file.getNameCiphertext())),
                string(cipher.decryptField(StoredFile.FIELD_CONTENT_TYPE, file.getContentTypeCiphertext())),
                file.getSizeBytes(),
                cipher.decryptField(StoredFile.FIELD_DIGEST, file.getDigestCiphertext()),
                file.getUploadedAt(),
                user.keyring().publicKeys().signingKeyFingerprint());
    }

    private void sign(ActiveUser user, StoredFile file, FileManifest manifest) {
        byte[] signature = user.keyring().use(keys -> signer.sign(keys, manifest));
        file.sign(FileManifest.ALGORITHM, manifest.signerKey(), signature);
    }

    /** Verifies against the session's (authentic) public key, never against a key from the database. */
    private SignatureStatus verify(ActiveUser user, StoredFile file, FileManifest manifest) {
        if (!file.isSigned()) {
            return SignatureStatus.UNSIGNED;
        }
        UserPublicKeys keys = user.keyring().publicKeys();
        boolean valid = FileManifest.ALGORITHM.equals(file.getSignatureAlgorithm())
                && signer.verify(keys.mlDsa(), manifest, file.getSignature());
        return valid ? SignatureStatus.VERIFIED : SignatureStatus.INVALID;
    }

    private byte[] digestOfContent(StoredFile file, ItemCipher cipher) throws IOException {
        MessageDigest sha3 = sha3();
        try (InputStream in = new DigestInputStream(cipher.decryptingStream(blobStore.open(file.getBlobKey())), sha3)) {
            in.transferTo(OutputStream.nullOutputStream());
        }
        return sha3.digest();
    }

    private byte[] nameTag(ActiveUser user, String name) {
        return user.keyring().use(keys -> {
            byte[] indexKey = keys.indexKey();
            try {
                return BlindIndex.tag(indexKey, NAME_TAG_PURPOSE, name);
            } finally {
                Bytes.wipe(indexKey);
            }
        });
    }

    private StoredFile find(ActiveUser user, UUID id) {
        return files.findByIdAndOwnerId(id, user.id()).orElseThrow(() -> new ItemNotFoundException(ItemKind.FILE, id));
    }

    private static MessageDigest sha3() {
        try {
            return MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA3-256 is required by the Java platform", e);
        }
    }
}
