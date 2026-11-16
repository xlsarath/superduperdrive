package io.github.xlsarath.superduperdrive.crypto.suite;

import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridKem;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPrivateKey;
import io.github.xlsarath.superduperdrive.crypto.kem.HybridPublicKey;
import io.github.xlsarath.superduperdrive.crypto.stream.SegmentedAeadInputStream;
import io.github.xlsarath.superduperdrive.crypto.stream.SegmentedAeadOutputStream;
import io.github.xlsarath.superduperdrive.crypto.support.AesGcm;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;
import io.github.xlsarath.superduperdrive.crypto.support.CanonicalEncoder;
import io.github.xlsarath.superduperdrive.crypto.support.Hkdf;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * {@code HYB-X25519-MLKEM768-AES256GCM-v1}: hybrid KEM envelope with AES-256-GCM content
 * encryption.
 *
 * <pre>
 *   header       = LP("SDD/ITEM") || LP(kind) || LP(item id) || LP(owner id) || LP(suite id) || LP(version)
 *   KEK, ct      = HybridKem.Encaps(pk_owner, context = header)
 *   DEK          = 32 random bytes (fresh for every seal and every re-key)
 *   wrapped DEK  = AES-256-GCM(KEK, random 96-bit nonce, aad = header, DEK)
 *   k_field      = HKDF-SHA-512(ikm = DEK, salt = "SDD/DEK/v1", info = "fields")
 *   k_content    = HKDF-SHA-512(ikm = DEK, salt = "SDD/DEK/v1", info = "content")
 *   field c/t    = nonce (12, random) || AES-256-GCM(k_field, nonce, aad = header || LP(field name), value)
 *   content      = segmented AES-256-GCM under k_content, aad = header || LP("content")
 * </pre>
 *
 * Separate subkeys keep random field nonces and counter-based stream nonces in disjoint key
 * spaces.
 */
public final class HybridAesGcmSuiteV1 implements EnvelopeSuite {

    public static final String ID = "HYB-X25519-MLKEM768-AES256GCM-v1";
    public static final int FORMAT_VERSION = 1;

    private static final SuiteDescriptor DESCRIPTOR = new SuiteDescriptor(ID, FORMAT_VERSION, SuiteStatus.CURRENT,
            "X25519 + ML-KEM-768 (FIPS 203), X-Wing-style combiner", "HKDF-SHA-512",
            "AES-256-GCM (96-bit nonce, 128-bit tag), 64 KiB STREAM segments for files", true);
    private static final byte[] DEK_SALT = "SDD/DEK/v1".getBytes(StandardCharsets.US_ASCII);
    private static final int DEK_BYTES = 32;

    private final HybridKem kem;
    private final SecureRandom random;
    private final int segmentBytes;

    public HybridAesGcmSuiteV1(SecureRandom random, int segmentBytes) {
        this.kem = new HybridKem(random);
        this.random = random;
        this.segmentBytes = segmentBytes;
    }

    @Override
    public SuiteDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public SealedDataKey newDataKey(ItemContext context, HybridPublicKey recipient) {
        byte[] header = header(context);
        HybridKem.Encapsulation encapsulation = kem.encapsulate(recipient, header);
        byte[] dek = new byte[DEK_BYTES];
        random.nextBytes(dek);
        byte[] nonce = AesGcm.newNonce(random);
        try {
            byte[] wrapped = AesGcm.seal(encapsulation.sharedKey(), nonce, header, dek);
            Envelope envelope = new Envelope(FORMAT_VERSION, encapsulation.ciphertext(), nonce, wrapped);
            return new SealedDataKey(ID, envelope, new GcmItemCipher(dek, header, random, segmentBytes));
        } finally {
            Bytes.wipe(dek, encapsulation.sharedKey());
        }
    }

    @Override
    public ItemCipher openDataKey(ItemContext context, Envelope envelope, HybridPrivateKey recipient) {
        if (envelope.formatVersion() != FORMAT_VERSION) {
            throw new UnsupportedSuiteException("envelope format " + envelope.formatVersion() + " is not " + ID);
        }
        byte[] header = header(context);
        byte[] kek = kem.decapsulate(recipient, envelope.kemCiphertext(), header);
        byte[] dek = null;
        try {
            dek = AesGcm.open(kek, envelope.wrapNonce(), header, envelope.wrappedDek());
            if (dek.length != DEK_BYTES) {
                throw new IntegrityException("unwrapped data key has the wrong length");
            }
            return new GcmItemCipher(dek, header, random, segmentBytes);
        } finally {
            Bytes.wipe(kek, dek);
        }
    }

    static byte[] header(ItemContext context) {
        return CanonicalEncoder.create()
                .add("SDD/ITEM")
                .add(context.kind().code())
                .add(context.itemId())
                .add(context.ownerId())
                .add(ID)
                .add(FORMAT_VERSION)
                .toByteArray();
    }

    /** DEK-scoped cipher. Copies and derives its subkeys, then wipes them on close. */
    private static final class GcmItemCipher implements ItemCipher {

        private final byte[] fieldKey;
        private final byte[] contentKey;
        private final byte[] header;
        private final SecureRandom random;
        private final int segmentBytes;
        private volatile boolean closed;

        GcmItemCipher(byte[] dek, byte[] header, SecureRandom random, int segmentBytes) {
            this.fieldKey = Hkdf.sha512(dek, DEK_SALT, "fields".getBytes(StandardCharsets.US_ASCII), AesGcm.KEY_BYTES);
            this.contentKey = Hkdf.sha512(dek, DEK_SALT, "content".getBytes(StandardCharsets.US_ASCII), AesGcm.KEY_BYTES);
            this.header = header;
            this.random = random;
            this.segmentBytes = segmentBytes;
        }

        @Override
        public byte[] encryptField(String field, byte[] plaintext) {
            checkOpen();
            byte[] nonce = AesGcm.newNonce(random);
            return Bytes.concat(nonce, AesGcm.seal(fieldKey, nonce, fieldAad(field), plaintext));
        }

        @Override
        public byte[] decryptField(String field, byte[] ciphertext) {
            checkOpen();
            if (ciphertext == null || ciphertext.length < AesGcm.NONCE_BYTES + AesGcm.TAG_BYTES) {
                throw new IntegrityException("field ciphertext is too short");
            }
            byte[] nonce = Arrays.copyOfRange(ciphertext, 0, AesGcm.NONCE_BYTES);
            byte[] body = Arrays.copyOfRange(ciphertext, AesGcm.NONCE_BYTES, ciphertext.length);
            return AesGcm.open(fieldKey, nonce, fieldAad(field), body);
        }

        @Override
        public OutputStream encryptingStream(OutputStream sink) throws IOException {
            checkOpen();
            return new SegmentedAeadOutputStream(sink, contentKey, contentAad(), segmentBytes, random);
        }

        @Override
        public InputStream decryptingStream(InputStream source) {
            checkOpen();
            return new SegmentedAeadInputStream(source, contentKey, contentAad());
        }

        @Override
        public void close() {
            closed = true;
            Bytes.wipe(fieldKey, contentKey);
        }

        private byte[] fieldAad(String field) {
            return Bytes.concat(header, CanonicalEncoder.create().add(field).toByteArray());
        }

        private byte[] contentAad() {
            return Bytes.concat(header, CanonicalEncoder.create().add("content").toByteArray());
        }

        private void checkOpen() {
            if (closed) {
                throw new IllegalStateException("item cipher is closed");
            }
        }
    }
}
