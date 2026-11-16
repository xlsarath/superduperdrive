package io.github.xlsarath.superduperdrive.service.item;

import java.time.Instant;
import java.util.UUID;

/** Decrypted file metadata for display, with the outcome of the signature check. */
public record FileView(UUID id, String name, String contentType, long size, Instant uploadedAt, String suiteId,
                       SignatureStatus signature, String signatureAlgorithm, boolean readable) {
}
