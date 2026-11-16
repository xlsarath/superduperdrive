package io.github.xlsarath.superduperdrive.service.item;

import java.util.Map;

/**
 * Exportable proof of provenance: the canonical statement, the ML-DSA-65 signature over its
 * JCS bytes, and the signer's public key (all Base64 where binary).
 */
public record SignedManifest(Map<String, Object> statement, String algorithm, String context, String signature,
                             String publicKey, boolean verified) {
}
