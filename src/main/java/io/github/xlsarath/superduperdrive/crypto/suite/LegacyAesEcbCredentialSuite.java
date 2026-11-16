package io.github.xlsarath.superduperdrive.crypto.suite;

import io.github.xlsarath.superduperdrive.crypto.IntegrityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * {@code LEGACY-AES192-ECB-PKCS5-v0}: how the 2020 version of this application stored website
 * passwords. <strong>Decrypt-only</strong>; it exists so old rows can be migrated to the
 * current suite and is the only place ECB appears in the code base.
 *
 * <p>The old code generated 16 random bytes, Base64-encoded them, and then used the
 * <em>bytes of the Base64 text</em> (24 ASCII characters) as the AES key. That is AES-192 in
 * ECB mode with PKCS#5 padding: deterministic, unauthenticated, and with the key stored in
 * the same row as the ciphertext. It provided obfuscation, not confidentiality.
 */
public final class LegacyAesEcbCredentialSuite implements CryptoSuite {

    public static final String ID = "LEGACY-AES192-ECB-PKCS5-v0";

    private static final SuiteDescriptor DESCRIPTOR = new SuiteDescriptor(ID, 0, SuiteStatus.LEGACY_DECRYPT_ONLY,
            "none (key stored beside the ciphertext)", "none", "AES-192-ECB, PKCS#5 padding, no authentication",
            false);

    @Override
    public SuiteDescriptor descriptor() {
        return DESCRIPTOR;
    }

    /**
     * @param base64Ciphertext the legacy {@code password} column
     * @param keyText          the legacy {@code key} column (Base64 text whose bytes are the key)
     * @return the plaintext bytes; the caller must wipe them
     */
    public byte[] decrypt(String base64Ciphertext, String keyText) {
        try {
            byte[] key = keyText.getBytes(StandardCharsets.US_ASCII);
            if (key.length != 16 && key.length != 24 && key.length != 32) {
                throw new IntegrityException("legacy key has an invalid length");
            }
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            return cipher.doFinal(Base64.getDecoder().decode(base64Ciphertext));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IntegrityException("legacy credential could not be decrypted", e);
        }
    }
}
