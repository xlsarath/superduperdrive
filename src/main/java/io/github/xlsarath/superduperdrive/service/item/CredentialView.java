package io.github.xlsarath.superduperdrive.service.item;

import java.util.UUID;

/**
 * Credential row for display. The password is never part of the list view: only a preview of
 * its ciphertext. {@link CredentialService#reveal} decrypts it on demand.
 */
public record CredentialView(UUID id, String url, String username, String passwordCiphertextPreview, String suiteId,
                             boolean readable) {
}
