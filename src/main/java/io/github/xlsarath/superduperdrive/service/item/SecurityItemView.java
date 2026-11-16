package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;

import java.time.Instant;
import java.util.UUID;

/** One row of the Security page. */
public record SecurityItemView(ItemKind kind, UUID id, String label, String suiteId, boolean currentSuite,
                               boolean quantumSafe, Instant sealedAt, String migratedFrom,
                               SignatureStatus signature, boolean readable) {
}
