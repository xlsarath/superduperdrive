package io.github.xlsarath.superduperdrive.service.item;

import java.time.Instant;
import java.util.UUID;

/** Decrypted note for display. {@code readable == false} means the ciphertext failed to authenticate. */
public record NoteView(UUID id, String title, String body, String suiteId, Instant updatedAt, boolean readable) {
}
