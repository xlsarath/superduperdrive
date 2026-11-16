package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;
import io.github.xlsarath.superduperdrive.crypto.sign.FileManifest;
import io.github.xlsarath.superduperdrive.crypto.sign.ManifestSigner;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ManifestSignerTest {

    private final ManifestSigner signer = new ManifestSigner(TestKeys.RANDOM);

    @Test
    void canonicalFormIsSortedCompactJson() {
        FileManifest manifest = new FileManifest(UUID.fromString("00000000-0000-0000-0000-000000000001"),
                UUID.fromString("00000000-0000-0000-0000-000000000002"), "a \"q\"\n.txt", "text/plain", 5,
                new byte[32], Instant.parse("2026-01-02T03:04:05.678912Z"), "ab");
        assertThat(new String(manifest.canonicalBytes(), StandardCharsets.UTF_8)).isEqualTo(
                "{\"algorithm\":\"ML-DSA-65\",\"contentType\":\"text/plain\",\"context\":\"SDD-FILE-MANIFEST-v1\","
                        + "\"fileId\":\"00000000-0000-0000-0000-000000000001\",\"fileName\":\"a \\\"q\\\"\\n.txt\","
                        + "\"format\":\"sdd-manifest/1\",\"ownerId\":\"00000000-0000-0000-0000-000000000002\","
                        + "\"sha3_256\":\"" + "00".repeat(32) + "\",\"signerKey\":\"ab\",\"size\":5,"
                        + "\"uploadedAt\":\"2026-01-02T03:04:05.678Z\"}");
    }

    @Test
    void signsAndVerifies() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            FileManifest manifest = manifest(keys, "report.txt", 42);
            byte[] signature = signer.sign(keys, manifest);
            assertThat(signature).hasSize(ManifestSigner.SIGNATURE_BYTES);
            assertThat(signer.verify(keys.publicKeys().mlDsa(), manifest, signature)).isTrue();
        }
    }

    @Test
    void anyChangeToTheStatementBreaksTheSignature() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            FileManifest manifest = manifest(keys, "report.txt", 42);
            byte[] signature = signer.sign(keys, manifest);
            FileManifest renamed = manifest(keys, "report2.txt", 42, manifest);
            FileManifest resized = manifest(keys, "report.txt", 43, manifest);
            assertThat(signer.verify(keys.publicKeys().mlDsa(), renamed, signature)).isFalse();
            assertThat(signer.verify(keys.publicKeys().mlDsa(), resized, signature)).isFalse();
            byte[] flipped = signature.clone();
            flipped[100] ^= 1;
            assertThat(signer.verify(keys.publicKeys().mlDsa(), manifest, flipped)).isFalse();
            assertThat(signer.verify(keys.publicKeys().mlDsa(), manifest, new byte[3])).isFalse();
        }
    }

    @Test
    void otherKeysDoNotVerify() {
        try (UserKeyMaterial keys = TestKeys.newKeys(); UserKeyMaterial other = TestKeys.newKeys()) {
            FileManifest manifest = manifest(keys, "report.txt", 42);
            byte[] signature = signer.sign(keys, manifest);
            assertThat(signer.verify(other.publicKeys().mlDsa(), manifest, signature)).isFalse();
        }
    }

    private static FileManifest manifest(UserKeyMaterial keys, String name, long size) {
        return new FileManifest(UUID.randomUUID(), UUID.randomUUID(), name, "text/plain", size, new byte[32],
                Instant.now(), keys.publicKeys().signingKeyFingerprint());
    }

    private static FileManifest manifest(UserKeyMaterial keys, String name, long size, FileManifest base) {
        return new FileManifest(base.fileId(), base.ownerId(), name, base.contentType(), size, base.sha3_256(),
                base.uploadedAt(), keys.publicKeys().signingKeyFingerprint());
    }
}
