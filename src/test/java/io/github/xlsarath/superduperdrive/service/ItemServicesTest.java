package io.github.xlsarath.superduperdrive.service;

import io.github.xlsarath.superduperdrive.config.DriveProperties;
import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPrivateKey;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPublicKey;
import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import io.github.xlsarath.superduperdrive.crypto.suite.EnvelopeSuite;
import io.github.xlsarath.superduperdrive.crypto.suite.HybridAesGcmSuiteV1;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemCipher;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemContext;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.crypto.suite.LegacyAesEcbCredentialSuite;
import io.github.xlsarath.superduperdrive.crypto.suite.SealedDataKey;
import io.github.xlsarath.superduperdrive.crypto.suite.SuiteDescriptor;
import io.github.xlsarath.superduperdrive.crypto.suite.SuiteStatus;
import io.github.xlsarath.superduperdrive.domain.Credential;
import io.github.xlsarath.superduperdrive.domain.Note;
import io.github.xlsarath.superduperdrive.domain.StoredFile;
import io.github.xlsarath.superduperdrive.repository.CredentialRepository;
import io.github.xlsarath.superduperdrive.repository.NoteRepository;
import io.github.xlsarath.superduperdrive.repository.StoredFileRepository;
import io.github.xlsarath.superduperdrive.service.item.CredentialService;
import io.github.xlsarath.superduperdrive.service.item.CredentialView;
import io.github.xlsarath.superduperdrive.service.item.CryptoMigrationService;
import io.github.xlsarath.superduperdrive.service.item.DuplicateFileNameException;
import io.github.xlsarath.superduperdrive.service.item.FileDownload;
import io.github.xlsarath.superduperdrive.service.item.FileService;
import io.github.xlsarath.superduperdrive.service.item.FileView;
import io.github.xlsarath.superduperdrive.service.item.NoteService;
import io.github.xlsarath.superduperdrive.service.item.NoteView;
import io.github.xlsarath.superduperdrive.service.item.SecurityOverview;
import io.github.xlsarath.superduperdrive.service.item.SecurityOverviewService;
import io.github.xlsarath.superduperdrive.service.item.SignatureStatus;
import io.github.xlsarath.superduperdrive.service.item.SignedManifest;
import io.github.xlsarath.superduperdrive.service.item.UploadRequest;
import io.github.xlsarath.superduperdrive.support.TestUsers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.test.context.ActiveProfiles;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Notes, credentials and files end to end through the services, the crypto layer and H2. */
@SpringBootTest
@ActiveProfiles("test")
class ItemServicesTest {

    @Autowired
    TestUsers testUsers;
    @Autowired
    NoteService notes;
    @Autowired
    CredentialService credentials;
    @Autowired
    FileService files;
    @Autowired
    CryptoMigrationService migration;
    @Autowired
    SecurityOverviewService securityOverview;
    @Autowired
    NoteRepository noteRepository;
    @Autowired
    CredentialRepository credentialRepository;
    @Autowired
    StoredFileRepository fileRepository;
    @Autowired
    DriveProperties properties;
    @Autowired
    RetiredTestSuite retiredSuite;

    // --- notes ----------------------------------------------------------------------------------

    @Test
    void notesRoundTripAndAreStoredEncrypted() {
        ActiveUser ada = testUsers.signedIn();
        UUID id = notes.save(ada, null, "Analytical Engine", "Bernoulli numbers, note G");

        assertThat(notes.list(ada)).singleElement().satisfies(view -> {
            assertThat(view.title()).isEqualTo("Analytical Engine");
            assertThat(view.body()).isEqualTo("Bernoulli numbers, note G");
            assertThat(view.readable()).isTrue();
        });
        Note row = noteRepository.findById(id).orElseThrow();
        assertThat(new String(row.getBodyCiphertext(), StandardCharsets.ISO_8859_1)).doesNotContain("Bernoulli");
        assertThat(row.getSuiteId()).isEqualTo(HybridAesGcmSuiteV1.ID);

        byte[] before = row.envelope().orElseThrow().wrappedDek();
        notes.save(ada, id, "Analytical Engine", "edited");
        Note edited = noteRepository.findById(id).orElseThrow();
        assertThat(edited.envelope().orElseThrow().wrappedDek()).isNotEqualTo(before);
        assertThat(notes.list(ada)).extracting(NoteView::body).containsExactly("edited");

        notes.delete(ada, id);
        assertThat(notes.list(ada)).isEmpty();
    }

    @Test
    void itemsOfOtherUsersAreInvisible() {
        ActiveUser ada = testUsers.signedIn();
        ActiveUser grace = testUsers.signedIn();
        UUID id = notes.save(ada, null, "private", "mine");

        assertThat(notes.list(grace)).isEmpty();
        assertThatThrownBy(() -> notes.delete(grace, id)).isInstanceOf(ItemNotFoundException.class);
        assertThatThrownBy(() -> notes.save(grace, id, "x", "y")).isInstanceOf(ItemNotFoundException.class);
        assertThatThrownBy(() -> credentials.reveal(grace, id)).isInstanceOf(ItemNotFoundException.class);
    }

    @Test
    void tamperedNotesAreReportedUnreadableNotServed() {
        ActiveUser ada = testUsers.signedIn();
        UUID id = notes.save(ada, null, "title", "body");
        Note row = noteRepository.findById(id).orElseThrow();
        byte[] body = row.getBodyCiphertext();
        body[body.length - 1] ^= 1;
        row.seal(row.getSuiteId(), row.envelope().orElseThrow(), row.getTitleCiphertext(), body, Instant.now());
        noteRepository.saveAndFlush(row);

        assertThat(notes.list(ada)).singleElement().satisfies(view -> {
            assertThat(view.readable()).isFalse();
            assertThat(view.body()).isEmpty();
        });
    }

    // --- credentials ----------------------------------------------------------------------------

    @Test
    void credentialsListOnlyCiphertextAndRevealOnDemand() {
        ActiveUser ada = testUsers.signedIn();
        UUID id = credentials.save(ada, null, "https://example.com", "ada", "difference-engine");

        CredentialView view = credentials.list(ada).getFirst();
        assertThat(view.url()).isEqualTo("https://example.com");
        assertThat(view.passwordCiphertextPreview()).isNotBlank().doesNotContain("difference");
        assertThat(credentials.reveal(ada, id)).isEqualTo("difference-engine");

        credentials.save(ada, id, "https://example.com/login", "ada.l", "");
        assertThat(credentials.reveal(ada, id)).isEqualTo("difference-engine");
        assertThat(credentials.list(ada).getFirst().username()).isEqualTo("ada.l");

        credentials.save(ada, id, "https://example.com/login", "ada.l", "new-secret");
        assertThat(credentials.reveal(ada, id)).isEqualTo("new-secret");
        assertThatThrownBy(() -> credentials.save(ada, null, "https://example.org", "x", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void legacyEcbCredentialsAreMigratedToTheHybridSuite() {
        ActiveUser ada = testUsers.signedIn();
        Credential legacy = credentialRepository.saveAndFlush(Credential.legacy(UUID.randomUUID(), ada.id(),
                LegacyAesEcbCredentialSuite.ID, "https://example.org", "grace", "kh1dzoGmM40lvT8+GnvE8Q==",
                "HUQHSPSbVLk92JyMNQgCF/7zIYsyJpm8erP3jnK2P9E="));
        assertThat(credentials.reveal(ada, legacy.getId())).isEqualTo("cobol-forever-1959");

        CryptoMigrationService.MigrationReport report = migration.migrateOutdatedItems(ada);

        assertThat(report.migrated()).isEqualTo(1);
        assertThat(report.failed()).isZero();
        Credential migrated = credentialRepository.findById(legacy.getId()).orElseThrow();
        assertThat(migrated.isLegacy()).isFalse();
        assertThat(migrated.getSuiteId()).isEqualTo(HybridAesGcmSuiteV1.ID);
        assertThat(migrated.getMigratedFromSuite()).contains(LegacyAesEcbCredentialSuite.ID);
        assertThat(migrated.getLegacyKey()).isNull();
        assertThat(migrated.getLegacyPassword()).isNull();
        assertThat(credentials.reveal(ada, legacy.getId())).isEqualTo("cobol-forever-1959");
        assertThat(migration.migrateOutdatedItems(ada).migrated()).isZero();
    }

    @Test
    void itemsOnARetiredSuiteAreReKeyedToTheCurrentOne() {
        ActiveUser ada = testUsers.signedIn();
        Note note = new Note(UUID.randomUUID(), ada.id());
        try (SealedDataKey key = retiredSuite.newDataKey(note.context(), ada.keyring().publicKeys().encryptionKey())) {
            note.seal(key.suiteId(), key.envelope(), key.cipher().encryptField(Note.FIELD_TITLE, "old".getBytes()),
                    key.cipher().encryptField(Note.FIELD_BODY, "suite".getBytes()), Instant.now());
        }
        noteRepository.saveAndFlush(note);
        SecurityOverview before = securityOverview.overview(ada);
        assertThat(before.outdatedCount()).isEqualTo(1);
        assertThat(before.suites()).extracting(SuiteDescriptor::id).contains(RetiredTestSuite.ID);

        assertThat(migration.migrateOutdatedItems(ada).migrated()).isEqualTo(1);

        Note after = noteRepository.findById(note.getId()).orElseThrow();
        assertThat(after.getSuiteId()).isEqualTo(HybridAesGcmSuiteV1.ID);
        assertThat(after.getMigratedFromSuite()).contains(RetiredTestSuite.ID);
        assertThat(notes.list(ada)).extracting(NoteView::title).containsExactly("old");
        assertThat(securityOverview.overview(ada).outdatedCount()).isZero();
    }

    // --- files ----------------------------------------------------------------------------------

    @Test
    void filesAreEncryptedSignedVerifiedAndStreamed() throws IOException {
        ActiveUser ada = testUsers.signedIn();
        byte[] content = new byte[200_000];
        new java.util.Random(7).nextBytes(content);
        UUID id = files.upload(ada, upload("notes/engine-plans.bin", "application/x-test", content));

        FileView view = files.list(ada).getFirst();
        assertThat(view.name()).isEqualTo("engine-plans.bin");
        assertThat(view.size()).isEqualTo(content.length);
        assertThat(view.signature()).isEqualTo(SignatureStatus.VERIFIED);

        StoredFile row = fileRepository.findById(id).orElseThrow();
        byte[] blob = Files.readAllBytes(blobPath(row.getBlobKey()));
        assertThat(blob.length).isGreaterThan(content.length);
        assertThat(indexOf(blob, java.util.Arrays.copyOf(content, 64))).isNegative();

        assertThat(download(ada, id)).isEqualTo(content);

        SignedManifest manifest = files.signedManifest(ada, id);
        assertThat(manifest.verified()).isTrue();
        assertThat(manifest.statement()).containsEntry("fileName", "engine-plans.bin").containsEntry("size", 200_000L);
        assertThat(manifest.algorithm()).isEqualTo("ML-DSA-65");
    }

    @Test
    void duplicateNamesAreRejectedCaseInsensitively() throws IOException {
        ActiveUser ada = testUsers.signedIn();
        files.upload(ada, upload("Report.txt", "text/plain", "one".getBytes()));
        assertThatThrownBy(() -> files.upload(ada, upload("report.TXT", "text/plain", "two".getBytes())))
                .isInstanceOf(DuplicateFileNameException.class);
        ActiveUser grace = testUsers.signedIn();
        files.upload(grace, upload("Report.txt", "text/plain", "three".getBytes()));
    }

    @Test
    void tamperedContentIsNeverReleased() throws IOException {
        ActiveUser ada = testUsers.signedIn();
        UUID id = files.upload(ada, upload("a.txt", "text/plain", "hello, analytical engine".getBytes()));
        Path blob = blobPath(fileRepository.findById(id).orElseThrow().getBlobKey());
        byte[] bytes = Files.readAllBytes(blob);
        bytes[bytes.length - 3] ^= 1;
        Files.write(blob, bytes);

        assertThatThrownBy(() -> files.download(ada, id)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void forgedSignaturesAreDetected() throws IOException {
        ActiveUser ada = testUsers.signedIn();
        UUID id = files.upload(ada, upload("b.txt", "text/plain", "signed".getBytes()));
        StoredFile row = fileRepository.findById(id).orElseThrow();
        byte[] signature = row.getSignature();
        signature[42] ^= 1;
        row.sign(row.getSignatureAlgorithm(), row.getSignerKeyFingerprint(), signature);
        fileRepository.saveAndFlush(row);

        assertThat(files.list(ada).getFirst().signature()).isEqualTo(SignatureStatus.INVALID);
        assertThatThrownBy(() -> files.download(ada, id)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void reKeyingReplacesTheBlobAndKeepsTheSignatureValid() throws IOException {
        ActiveUser ada = testUsers.signedIn();
        UUID id = files.upload(ada, upload("c.txt", "text/plain", "re-key me".getBytes()));
        String oldBlob = fileRepository.findById(id).orElseThrow().getBlobKey();

        migration.rekey(ada, ItemKind.FILE, id);

        StoredFile row = fileRepository.findById(id).orElseThrow();
        assertThat(row.getBlobKey()).isNotEqualTo(oldBlob);
        assertThat(Files.exists(blobPath(oldBlob))).isFalse();
        assertThat(files.list(ada).getFirst().signature()).isEqualTo(SignatureStatus.VERIFIED);
        assertThat(download(ada, id)).isEqualTo("re-key me".getBytes());
    }

    @Test
    void deletingAFileRemovesItsBlobAfterCommit() throws IOException {
        ActiveUser ada = testUsers.signedIn();
        UUID id = files.upload(ada, upload("d.txt", "text/plain", "bye".getBytes()));
        Path blob = blobPath(fileRepository.findById(id).orElseThrow().getBlobKey());
        files.delete(ada, id);
        assertThat(fileRepository.findById(id)).isEmpty();
        assertThat(Files.exists(blob)).isFalse();
    }

    @Test
    void emptyFilesAreSupported() throws IOException {
        ActiveUser ada = testUsers.signedIn();
        UUID id = files.upload(ada, upload("empty.txt", "text/plain", new byte[0]));
        assertThat(download(ada, id)).isEmpty();
    }

    // --- helpers --------------------------------------------------------------------------------

    private byte[] download(ActiveUser user, UUID id) throws IOException {
        FileDownload download = files.download(user, id);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        download.content().writeTo(out);
        return out.toByteArray();
    }

    private Path blobPath(String key) {
        return properties.storage().blobDirectory().resolve(key.substring(0, 2)).resolve(key + ".sdd");
    }

    private static UploadRequest upload(String name, String type, byte[] content) {
        return new UploadRequest(name, type, new ByteArrayResource(content));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * Stand-in for a suite that has been superseded: same primitives as v1, different id. Proves
     * that the registry routes by the persisted id and that migration moves items forward.
     */
    static final class RetiredTestSuite implements EnvelopeSuite {

        static final String ID = "TEST-RETIRED-SUITE-v0";
        private final HybridAesGcmSuiteV1 delegate = new HybridAesGcmSuiteV1(new java.security.SecureRandom(), 65536);

        @Override
        public SuiteDescriptor descriptor() {
            return new SuiteDescriptor(ID, 0, SuiteStatus.SUPPORTED, "test", "test", "test", false);
        }

        @Override
        public SealedDataKey newDataKey(ItemContext context, HybridPublicKey recipient) {
            SealedDataKey key = delegate.newDataKey(context, recipient);
            return new SealedDataKey(ID, key.envelope(), key.cipher());
        }

        @Override
        public ItemCipher openDataKey(ItemContext context, Envelope envelope, HybridPrivateKey recipient) {
            return delegate.openDataKey(context, envelope, recipient);
        }
    }

    @TestConfiguration
    static class RetiredSuiteConfiguration {
        @Bean
        RetiredTestSuite retiredTestSuite() {
            return new RetiredTestSuite();
        }
    }
}
