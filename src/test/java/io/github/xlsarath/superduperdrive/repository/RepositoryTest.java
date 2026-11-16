package io.github.xlsarath.superduperdrive.repository;

import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import io.github.xlsarath.superduperdrive.crypto.suite.HybridAesGcmSuiteV1;
import io.github.xlsarath.superduperdrive.crypto.suite.LegacyAesEcbCredentialSuite;
import io.github.xlsarath.superduperdrive.domain.Credential;
import io.github.xlsarath.superduperdrive.domain.Note;
import io.github.xlsarath.superduperdrive.domain.StoredFile;
import io.github.xlsarath.superduperdrive.domain.UserAccount;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import io.github.xlsarath.superduperdrive.config.ApplicationConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import io.github.xlsarath.superduperdrive.config.DriveProperties;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Flyway schema + JPA mapping + derived queries against H2 in PostgreSQL mode. */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
@Import(ApplicationConfiguration.class)
@EnableConfigurationProperties(DriveProperties.class)
class RepositoryTest {

    @Autowired
    UserAccountRepository users;
    @Autowired
    NoteRepository notes;
    @Autowired
    CredentialRepository credentials;
    @Autowired
    StoredFileRepository files;

    private UUID ada;
    private UUID grace;
    private final Envelope envelope = new Envelope(1, new byte[1120], new byte[12], new byte[48]);

    @BeforeEach
    void users() {
        ada = users.save(new UserAccount(UUID.randomUUID(), "ada", "{argon2}x", "Ada", "Lovelace")).getId();
        grace = users.save(new UserAccount(UUID.randomUUID(), "grace", "{argon2}x", "Grace", "Hopper")).getId();
    }

    @Test
    void usernamesAreUnique() {
        assertThat(users.existsByUsername("ada")).isTrue();
        assertThatThrownBy(() -> users.saveAndFlush(new UserAccount(UUID.randomUUID(), "ada", "h", "A", "L")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void lookupsAreScopedByOwner() {
        Note note = new Note(UUID.randomUUID(), ada);
        note.seal(HybridAesGcmSuiteV1.ID, envelope, new byte[] {1}, new byte[] {2}, Instant.now());
        notes.saveAndFlush(note);

        assertThat(notes.findByIdAndOwnerId(note.getId(), ada)).isPresent();
        assertThat(notes.findByIdAndOwnerId(note.getId(), grace)).isEmpty();
        assertThat(notes.findAllByOwnerIdOrderByCreatedAtAsc(grace)).isEmpty();
        assertThat(notes.countByOwnerId(ada)).isEqualTo(1);
    }

    @Test
    void migrationWorkListFindsItemsOnOtherSuites() {
        Credential legacy = Credential.legacy(UUID.randomUUID(), ada, LegacyAesEcbCredentialSuite.ID,
                "https://example.com", "ada", "kh1dzoGmM40lvT8+GnvE8Q==", "HUQHSPSbVLk92JyMNQgCF/7zIYsyJpm8erP3jnK2P9E=");
        Credential current = new Credential(UUID.randomUUID(), ada);
        current.seal(HybridAesGcmSuiteV1.ID, envelope, new byte[] {1}, new byte[] {2}, new byte[] {3}, Instant.now());
        credentials.saveAllAndFlush(java.util.List.of(legacy, current));

        assertThat(credentials.findAllByOwnerIdAndSuiteIdNot(ada, HybridAesGcmSuiteV1.ID))
                .extracting(Credential::getId).containsExactly(legacy.getId());
    }

    @Test
    void credentialsMustBeEitherSealedOrLegacy() {
        Credential neither = new Credential(UUID.randomUUID(), ada);
        neither.seal(HybridAesGcmSuiteV1.ID, envelope, new byte[] {1}, new byte[] {2}, new byte[] {3}, Instant.now());
        credentials.saveAndFlush(neither);
        assertThat(credentials.findById(neither.getId())).get().extracting(Credential::isLegacy).isEqualTo(false);
    }

    @Test
    void fileNamesAreUniquePerOwnerViaTheBlindIndex() {
        byte[] tag = new byte[32];
        files.saveAndFlush(file(ada, tag));
        assertThat(files.existsByOwnerIdAndNameTag(ada, tag)).isTrue();
        assertThat(files.existsByOwnerIdAndNameTag(grace, tag)).isFalse();
        files.saveAndFlush(file(grace, tag)); // same tag, other owner: fine
        assertThatThrownBy(() -> files.saveAndFlush(file(ada, tag))).isInstanceOf(DataIntegrityViolationException.class);
    }

    private StoredFile file(UUID owner, byte[] tag) {
        StoredFile file = new StoredFile(UUID.randomUUID(), owner, tag, Instant.now());
        file.seal(HybridAesGcmSuiteV1.ID, envelope, UUID.randomUUID().toString(), 3, new byte[] {1}, new byte[] {2},
                new byte[] {3}, Instant.now());
        return file;
    }
}
