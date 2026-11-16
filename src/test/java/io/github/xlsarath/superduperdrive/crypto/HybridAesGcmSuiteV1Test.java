package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;
import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import io.github.xlsarath.superduperdrive.crypto.suite.HybridAesGcmSuiteV1;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemCipher;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemContext;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.crypto.suite.SealedDataKey;
import io.github.xlsarath.superduperdrive.crypto.suite.UnsupportedSuiteException;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HybridAesGcmSuiteV1Test {

    private final HybridAesGcmSuiteV1 suite = new HybridAesGcmSuiteV1(TestKeys.RANDOM, 4096);
    private final UserKeyMaterial owner = TestKeys.newKeys();
    private final ItemContext context = new ItemContext(ItemKind.NOTE, UUID.randomUUID(), UUID.randomUUID());

    @AfterEach
    void wipe() {
        owner.close();
    }

    @Test
    void fieldsRoundTrip() {
        byte[] ciphertext;
        Envelope envelope;
        try (SealedDataKey key = suite.newDataKey(context, owner.publicKeys().encryptionKey())) {
            assertThat(key.suiteId()).isEqualTo("HYB-X25519-MLKEM768-AES256GCM-v1");
            ciphertext = key.cipher().encryptField("title", utf8("Lovelace's notes"));
            envelope = key.envelope();
        }
        assertThat(new String(ciphertext, StandardCharsets.UTF_8)).doesNotContain("Lovelace");
        try (ItemCipher cipher = suite.openDataKey(context, envelope, owner.hybridPrivateKey())) {
            assertThat(cipher.decryptField("title", ciphertext)).isEqualTo(utf8("Lovelace's notes"));
        }
    }

    @Test
    void sameValueEncryptsDifferentlyEachTime() {
        try (SealedDataKey key = suite.newDataKey(context, owner.publicKeys().encryptionKey())) {
            assertThat(key.cipher().encryptField("f", utf8("x"))).isNotEqualTo(key.cipher().encryptField("f", utf8("x")));
        }
    }

    @Test
    void detectsCiphertextTampering() {
        Sealed sealed = seal("secret");
        byte[] tampered = sealed.ciphertext.clone();
        tampered[tampered.length - 1] ^= 0x01;
        try (ItemCipher cipher = suite.openDataKey(context, sealed.envelope, owner.hybridPrivateKey())) {
            assertThatThrownBy(() -> cipher.decryptField("title", tampered)).isInstanceOf(IntegrityException.class);
            assertThatThrownBy(() -> cipher.decryptField("title", new byte[5])).isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void fieldNameIsAuthenticated() {
        Sealed sealed = seal("secret");
        try (ItemCipher cipher = suite.openDataKey(context, sealed.envelope, owner.hybridPrivateKey())) {
            assertThatThrownBy(() -> cipher.decryptField("body", sealed.ciphertext)).isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void wrongKeyCannotOpenTheEnvelope() {
        Sealed sealed = seal("secret");
        try (UserKeyMaterial other = TestKeys.newKeys()) {
            assertThatThrownBy(() -> suite.openDataKey(context, sealed.envelope, other.hybridPrivateKey()))
                    .isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void envelopeCannotBeTransplantedToAnotherItemOwnerOrKind() {
        Sealed sealed = seal("secret");
        ItemContext otherItem = new ItemContext(context.kind(), UUID.randomUUID(), context.ownerId());
        ItemContext otherOwner = new ItemContext(context.kind(), context.itemId(), UUID.randomUUID());
        ItemContext otherKind = new ItemContext(ItemKind.CREDENTIAL, context.itemId(), context.ownerId());
        for (ItemContext wrong : new ItemContext[] {otherItem, otherOwner, otherKind}) {
            assertThatThrownBy(() -> suite.openDataKey(wrong, sealed.envelope, owner.hybridPrivateKey()))
                    .isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void tamperedEnvelopePartsAreRejected() {
        Sealed sealed = seal("secret");
        Envelope e = sealed.envelope;
        byte[] kem = e.kemCiphertext();
        kem[500] ^= 1;
        byte[] dek = e.wrappedDek();
        dek[0] ^= 1;
        byte[] nonce = e.wrapNonce();
        nonce[0] ^= 1;
        for (Envelope bad : new Envelope[] {
                new Envelope(1, kem, e.wrapNonce(), e.wrappedDek()),
                new Envelope(1, e.kemCiphertext(), e.wrapNonce(), dek),
                new Envelope(1, e.kemCiphertext(), nonce, e.wrappedDek())}) {
            assertThatThrownBy(() -> suite.openDataKey(context, bad, owner.hybridPrivateKey()))
                    .isInstanceOf(IntegrityException.class);
        }
        Envelope futureVersion = new Envelope(2, e.kemCiphertext(), e.wrapNonce(), e.wrappedDek());
        assertThatThrownBy(() -> suite.openDataKey(context, futureVersion, owner.hybridPrivateKey()))
                .isInstanceOf(UnsupportedSuiteException.class);
    }

    @Test
    void streamsRoundTripAndAreBoundToTheItem() throws IOException {
        byte[] content = new byte[10_000];
        TestKeys.RANDOM.nextBytes(content);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        Envelope envelope;
        try (SealedDataKey key = suite.newDataKey(context, owner.publicKeys().encryptionKey());
             OutputStream out = key.cipher().encryptingStream(sink)) {
            out.write(content);
            envelope = key.envelope();
        }
        try (ItemCipher cipher = suite.openDataKey(context, envelope, owner.hybridPrivateKey());
             InputStream in = cipher.decryptingStream(new ByteArrayInputStream(sink.toByteArray()))) {
            assertThat(in.readAllBytes()).isEqualTo(content);
        }
    }

    @Test
    void closedCipherRefusesWork() {
        SealedDataKey key = suite.newDataKey(context, owner.publicKeys().encryptionKey());
        key.close();
        assertThatThrownBy(() -> key.cipher().encryptField("f", utf8("x"))).isInstanceOf(IllegalStateException.class);
    }

    private Sealed seal(String value) {
        try (SealedDataKey key = suite.newDataKey(context, owner.publicKeys().encryptionKey())) {
            return new Sealed(key.envelope(), key.cipher().encryptField("title", utf8(value)));
        }
    }

    private record Sealed(Envelope envelope, byte[] ciphertext) {
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
