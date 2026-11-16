package io.github.xlsarath.superduperdrive.crypto.support;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/** HKDF (RFC 5869) instantiated with SHA-512, used for every key derivation in the code base. */
public final class Hkdf {

    private Hkdf() {
    }

    public static byte[] sha512(byte[] ikm, byte[] salt, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA512Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[length];
        hkdf.generateBytes(out, 0, length);
        return out;
    }
}
