package io.github.xlsarath.superduperdrive.service.item;

/** Outcome of checking a file's ML-DSA-65 manifest signature. */
public enum SignatureStatus {
    VERIFIED("Verified", "ML-DSA-65 signature over the manifest verified with your public key"),
    INVALID("Invalid", "The signature or the manifest it covers does not verify"),
    UNSIGNED("Unsigned", "No signature recorded for this item"),
    NOT_APPLICABLE("n/a", "Notes and credentials are authenticated by AES-GCM but not signed");

    private final String label;
    private final String description;

    SignatureStatus(String label, String description) {
        this.label = label;
        this.description = description;
    }

    public String label() {
        return label;
    }

    public String description() {
        return description;
    }
}
