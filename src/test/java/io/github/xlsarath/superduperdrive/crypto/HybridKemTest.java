package io.github.xlsarath.superduperdrive.crypto;

import io.github.xlsarath.superduperdrive.crypto.kem.HybridKem;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPrivateKey;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPublicKey;
import io.github.xlsarath.superduperdrive.crypto.keys.UserKeyMaterial;
import io.github.xlsarath.superduperdrive.support.TestKeys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HybridKemTest {

    private static final byte[] CONTEXT = "item-1".getBytes(StandardCharsets.UTF_8);
    private final HybridKem kem = new HybridKem(TestKeys.RANDOM);

    @Test
    void encapsulationRoundTripsToTheSameKey() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            HybridPrivateKey privateKey = keys.hybridPrivateKey();
            HybridKem.Encapsulation enc = kem.encapsulate(privateKey.publicKey(), CONTEXT);

            assertThat(enc.ciphertext()).hasSize(HybridKem.CIPHERTEXT_BYTES).hasSize(32 + 1088);
            assertThat(enc.sharedKey()).hasSize(32);
            assertThat(kem.decapsulate(privateKey, enc.ciphertext(), CONTEXT)).isEqualTo(enc.sharedKey());
        }
    }

    @Test
    void everyEncapsulationIsFresh() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            HybridPublicKey pk = keys.hybridPrivateKey().publicKey();
            HybridKem.Encapsulation a = kem.encapsulate(pk, CONTEXT);
            HybridKem.Encapsulation b = kem.encapsulate(pk, CONTEXT);
            assertThat(a.ciphertext()).isNotEqualTo(b.ciphertext());
            assertThat(a.sharedKey()).isNotEqualTo(b.sharedKey());
        }
    }

    @Test
    void wrongRecipientDerivesADifferentKey() {
        try (UserKeyMaterial alice = TestKeys.newKeys(); UserKeyMaterial mallory = TestKeys.newKeys()) {
            HybridKem.Encapsulation enc = kem.encapsulate(alice.hybridPrivateKey().publicKey(), CONTEXT);
            assertThat(kem.decapsulate(mallory.hybridPrivateKey(), enc.ciphertext(), CONTEXT))
                    .isNotEqualTo(enc.sharedKey());
        }
    }

    @Test
    void contextIsBoundIntoTheKey() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            HybridKem.Encapsulation enc = kem.encapsulate(keys.hybridPrivateKey().publicKey(), CONTEXT);
            byte[] other = kem.decapsulate(keys.hybridPrivateKey(), enc.ciphertext(), "item-2".getBytes(StandardCharsets.UTF_8));
            assertThat(other).isNotEqualTo(enc.sharedKey());
        }
    }

    @Test
    void tamperingWithEitherComponentChangesTheKey() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            HybridPrivateKey sk = keys.hybridPrivateKey();
            HybridKem.Encapsulation enc = kem.encapsulate(sk.publicKey(), CONTEXT);

            byte[] badX25519 = enc.ciphertext().clone();
            badX25519[3] ^= 0x01;
            byte[] badMlKem = enc.ciphertext().clone();
            badMlKem[100] ^= 0x01; // ML-KEM implicit rejection: no exception, a pseudorandom key

            assertThat(kem.decapsulate(sk, badX25519, CONTEXT)).isNotEqualTo(enc.sharedKey());
            assertThat(kem.decapsulate(sk, badMlKem, CONTEXT)).isNotEqualTo(enc.sharedKey());
        }
    }

    @Test
    void rejectsMalformedCiphertexts() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            HybridPrivateKey sk = keys.hybridPrivateKey();
            assertThatThrownBy(() -> kem.decapsulate(sk, new byte[10], CONTEXT)).isInstanceOf(IntegrityException.class);
            byte[] smallOrder = new byte[HybridKem.CIPHERTEXT_BYTES]; // all-zero X25519 share
            assertThatThrownBy(() -> kem.decapsulate(sk, smallOrder, CONTEXT)).isInstanceOf(IntegrityException.class);
        }
    }

    @Test
    void rejectsSmallOrderRecipientKey() {
        byte[] mlKem;
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            mlKem = keys.hybridPrivateKey().publicKey().mlKem();
        }
        HybridPublicKey evil = new HybridPublicKey(new byte[32], mlKem);
        assertThatThrownBy(() -> kem.encapsulate(evil, CONTEXT)).isInstanceOf(CryptoException.class);
    }

    @Test
    void privateKeyRoundTripsThroughItsEncoding() {
        try (UserKeyMaterial keys = TestKeys.newKeys()) {
            byte[] encoded = keys.encode();
            try (UserKeyMaterial copy = UserKeyMaterial.decode(encoded)) {
                assertThat(copy.publicKeys()).isEqualTo(keys.publicKeys());
            }
            Arrays.fill(encoded, (byte) 0);
        }
    }

    @Test
    void closedKeyMaterialCannotBeUsed() {
        UserKeyMaterial keys = TestKeys.newKeys();
        keys.close();
        assertThat(keys.isDestroyed()).isTrue();
        assertThatThrownBy(keys::hybridPrivateKey).isInstanceOf(IllegalStateException.class);
    }
}
