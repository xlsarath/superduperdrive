package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemCipher;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.crypto.suite.SealedDataKey;
import io.github.xlsarath.superduperdrive.domain.Note;
import io.github.xlsarath.superduperdrive.repository.NoteRepository;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.ItemNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.UUID;

import static io.github.xlsarath.superduperdrive.service.item.ItemCrypto.string;
import static io.github.xlsarath.superduperdrive.service.item.ItemCrypto.utf8;

/** Encrypted notes. Every save re-seals the whole note with a fresh data key. */
@Service
public class NoteService implements SealedItemHandler {

    private static final Logger log = LoggerFactory.getLogger(NoteService.class);

    private final NoteRepository notes;
    private final ItemCrypto crypto;
    private final Clock clock;

    public NoteService(NoteRepository notes, ItemCrypto crypto, Clock clock) {
        this.notes = notes;
        this.crypto = crypto;
        this.clock = clock;
    }

    @Override
    public ItemKind kind() {
        return ItemKind.NOTE;
    }

    @Transactional(readOnly = true)
    public List<NoteView> list(ActiveUser user) {
        return notes.findAllByOwnerIdOrderByCreatedAtAsc(user.id()).stream().map(note -> view(user, note)).toList();
    }

    /** Creates a note ({@code id == null}) or replaces an existing one. Returns the note id. */
    @Transactional
    public UUID save(ActiveUser user, UUID id, String title, String body) {
        Note note = id == null ? new Note(UUID.randomUUID(), user.id()) : find(user, id);
        seal(user, note, title, body);
        notes.save(note);
        log.info("{} note {} for user {} with suite {}", id == null ? "Created" : "Updated", note.getId(), user.id(),
                note.getSuiteId());
        return note.getId();
    }

    @Transactional
    public void delete(ActiveUser user, UUID id) {
        notes.delete(find(user, id));
        log.info("Deleted note {} for user {}", id, user.id());
    }

    @Override
    @Transactional(readOnly = true)
    public List<UUID> outdatedItemIds(ActiveUser user) {
        return notes.findAllByOwnerIdAndSuiteIdNot(user.id(), crypto.currentSuiteId()).stream()
                .map(Note::getId).toList();
    }

    @Override
    @Transactional
    public void rekey(ActiveUser user, UUID itemId) {
        Note note = find(user, itemId);
        String previous = note.getSuiteId();
        String title;
        String body;
        try (ItemCipher cipher = crypto.open(note, user)) {
            title = string(cipher.decryptField(Note.FIELD_TITLE, note.getTitleCiphertext()));
            body = string(cipher.decryptField(Note.FIELD_BODY, note.getBodyCiphertext()));
        }
        seal(user, note, title, body);
        notes.save(note);
        log.info("Re-keyed note {} for user {}: {} -> {}", itemId, user.id(), previous, note.getSuiteId());
    }

    @Override
    @Transactional(readOnly = true)
    public List<SecurityItemView> describe(ActiveUser user) {
        return notes.findAllByOwnerIdOrderByCreatedAtAsc(user.id()).stream().map(note -> {
            NoteView view = view(user, note);
            var suite = crypto.registry().descriptor(note.getSuiteId());
            return new SecurityItemView(ItemKind.NOTE, note.getId(), view.title(), note.getSuiteId(),
                    crypto.registry().isCurrent(note.getSuiteId()), suite.quantumSafe(), note.getSealedAt(),
                    note.getMigratedFromSuite().orElse(null), SignatureStatus.NOT_APPLICABLE, view.readable());
        }).toList();
    }

    private void seal(ActiveUser user, Note note, String title, String body) {
        try (SealedDataKey key = crypto.newDataKey(note, user)) {
            note.seal(key.suiteId(), key.envelope(),
                    key.cipher().encryptField(Note.FIELD_TITLE, utf8(title)),
                    key.cipher().encryptField(Note.FIELD_BODY, utf8(body)),
                    clock.instant());
        }
    }

    private NoteView view(ActiveUser user, Note note) {
        try (ItemCipher cipher = crypto.open(note, user)) {
            return new NoteView(note.getId(),
                    string(cipher.decryptField(Note.FIELD_TITLE, note.getTitleCiphertext())),
                    string(cipher.decryptField(Note.FIELD_BODY, note.getBodyCiphertext())),
                    note.getSuiteId(), note.getUpdatedAt(), true);
        } catch (CryptoException e) {
            log.warn("Note {} of user {} failed to decrypt ({}): {}", note.getId(), user.id(), note.getSuiteId(),
                    e.getMessage());
            return new NoteView(note.getId(), "Unreadable note", "", note.getSuiteId(), note.getUpdatedAt(), false);
        }
    }

    private Note find(ActiveUser user, UUID id) {
        return notes.findByIdAndOwnerId(id, user.id()).orElseThrow(() -> new ItemNotFoundException(ItemKind.NOTE, id));
    }
}
