package io.github.xlsarath.superduperdrive.crypto.support;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.text.Normalizer;
import java.util.Locale;

/**
 * Keyed, deterministic lookup tags ("blind indexes"): HMAC-SHA3-256 under a per-user index key.
 *
 * <p>Lets the database enforce uniqueness of, for example, file names per user with a plain
 * unique constraint, without the server learning the names. Equal inputs produce equal tags
 * for the same user, which is exactly the (documented) leakage of a uniqueness check.
 */
public final class BlindIndex {

    private BlindIndex() {
    }

    /** Case-insensitive, Unicode-normalised (NFC) tag for {@code value} under {@code purpose}. */
    public static byte[] tag(byte[] indexKey, String purpose, String value) {
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
        byte[] message = CanonicalEncoder.create().add("SDD/BLIND-INDEX/v1").add(purpose).add(normalized).toByteArray();
        HMac hmac = new HMac(new SHA3Digest(256));
        hmac.init(new KeyParameter(indexKey));
        hmac.update(message, 0, message.length);
        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }
}
