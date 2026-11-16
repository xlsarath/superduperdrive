package io.github.xlsarath.superduperdrive.crypto.support;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;

/**
 * AES-256-GCM with a 96-bit nonce and a 128-bit tag, via the Bouncy Castle lightweight API.
 *
 * <p>Decryption only returns plaintext after the tag has verified: the output buffer is
 * private to this method until {@code doFinal} succeeds.
 */
public final class AesGcm {

    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 16;
    private static final int TAG_BITS = TAG_BYTES * 8;

    private AesGcm() {
    }

    public static byte[] newNonce(SecureRandom random) {
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        return nonce;
    }

    public static byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        GCMModeCipher gcm = init(true, key, nonce, aad);
        byte[] out = new byte[gcm.getOutputSize(plaintext.length)];
        int written = gcm.processBytes(plaintext, 0, plaintext.length, out, 0);
        try {
            gcm.doFinal(out, written);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException("AES-GCM encryption failed", e);
        }
        return out;
    }

    public static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) {
        if (ciphertext.length < TAG_BYTES) {
            throw new IntegrityException("ciphertext shorter than the authentication tag");
        }
        GCMModeCipher gcm = init(false, key, nonce, aad);
        byte[] out = new byte[gcm.getOutputSize(ciphertext.length)];
        int written = gcm.processBytes(ciphertext, 0, ciphertext.length, out, 0);
        try {
            gcm.doFinal(out, written);
            return out;
        } catch (InvalidCipherTextException e) {
            Bytes.wipe(out);
            throw new IntegrityException("authentication tag mismatch", e);
        }
    }

    private static GCMModeCipher init(boolean encrypt, byte[] key, byte[] nonce, byte[] aad) {
        Bytes.requireLength(key, KEY_BYTES, "AES-256 key");
        Bytes.requireLength(nonce, NONCE_BYTES, "GCM nonce");
        GCMModeCipher gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcm.init(encrypt, new AEADParameters(new KeyParameter(key), TAG_BITS, nonce, aad));
        return gcm;
    }
}
