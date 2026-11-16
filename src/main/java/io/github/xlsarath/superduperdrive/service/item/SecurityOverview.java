package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.suite.SuiteDescriptor;

import java.time.Instant;
import java.util.List;

/**
 * Everything the Security page shows.
 *
 * @param keySuite                  user key-set identifier
 * @param encryptionKeyFingerprint  SHA3-256 of the X25519 and ML-KEM-768 public keys
 * @param signingKeyFingerprint     SHA3-256 of the ML-DSA-65 public key
 * @param keyWrap                   description of the password key-wrap (Argon2id cost)
 * @param keysCreatedAt             when the key pairs were generated
 * @param recoveryKeyIssuedAt       when the current recovery key was issued
 * @param suites                    every registered suite
 * @param items                     every item with its suite and signature status
 */
public record SecurityOverview(String keySuite, String encryptionKeyFingerprint, String signingKeyFingerprint,
                               String keyWrap, String keyWrapMethod, Instant keysCreatedAt, Instant recoveryKeyIssuedAt,
                               List<SuiteDescriptor> suites, List<SecurityItemView> items) {

    public long outdatedCount() {
        return items.stream().filter(item -> !item.currentSuite()).count();
    }

    public long verifiedFiles() {
        return items.stream().filter(item -> item.signature() == SignatureStatus.VERIFIED).count();
    }
}
