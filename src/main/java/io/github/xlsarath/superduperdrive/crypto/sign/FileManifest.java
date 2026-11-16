package io.github.xlsarath.superduperdrive.crypto.sign;

import io.github.xlsarath.superduperdrive.crypto.support.Bytes;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;

/**
 * The statement an uploader signs for each file. The signed message is the RFC 8785 (JCS)
 * canonical JSON of {@link #toCanonicalMap()}: keys sorted, no whitespace, strings escaped as in
 * ECMAScript {@code JSON.stringify}. Values are restricted to strings and non-negative integers,
 * which keeps the canonical form trivially reproducible by any verifier.
 *
 * @param fileId      item id
 * @param ownerId     uploader's account id
 * @param fileName    original file name (control characters rejected at upload)
 * @param contentType declared media type
 * @param size        plaintext size in bytes
 * @param sha3_256    SHA3-256 of the plaintext
 * @param uploadedAt  upload time, truncated to milliseconds so it survives a database round trip
 * @param signerKey   SHA3-256 fingerprint of the signer's ML-DSA-65 public key (hex)
 */
public record FileManifest(UUID fileId, UUID ownerId, String fileName, String contentType, long size,
                           byte[] sha3_256, Instant uploadedAt, String signerKey) {

    public static final String FORMAT = "sdd-manifest/1";
    public static final String ALGORITHM = "ML-DSA-65";
    public static final String CONTEXT = "SDD-FILE-MANIFEST-v1";

    public FileManifest {
        Objects.requireNonNull(fileId, "fileId");
        Objects.requireNonNull(ownerId, "ownerId");
        Objects.requireNonNull(fileName, "fileName");
        Objects.requireNonNull(contentType, "contentType");
        Objects.requireNonNull(signerKey, "signerKey");
        Bytes.requireLength(sha3_256, 32, "SHA3-256 digest");
        if (size < 0) {
            throw new IllegalArgumentException("size must not be negative");
        }
        sha3_256 = sha3_256.clone();
        uploadedAt = uploadedAt.truncatedTo(ChronoUnit.MILLIS);
    }

    @Override
    public byte[] sha3_256() {
        return sha3_256.clone();
    }

    public String sha3Hex() {
        return Bytes.hex(sha3_256);
    }

    /** The statement as an ordered map (used for both signing and the exported manifest). */
    public Map<String, Object> toCanonicalMap() {
        Map<String, Object> statement = new TreeMap<>();
        statement.put("algorithm", ALGORITHM);
        statement.put("contentType", contentType);
        statement.put("context", CONTEXT);
        statement.put("fileId", fileId.toString());
        statement.put("fileName", fileName);
        statement.put("format", FORMAT);
        statement.put("ownerId", ownerId.toString());
        statement.put("sha3_256", sha3Hex());
        statement.put("signerKey", signerKey);
        statement.put("size", size);
        statement.put("uploadedAt", DateTimeFormatter.ISO_INSTANT.format(uploadedAt));
        return statement;
    }

    /** UTF-8 bytes of the JCS canonical JSON form: the exact message passed to ML-DSA. */
    public byte[] canonicalBytes() {
        StringBuilder json = new StringBuilder(512).append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : toCanonicalMap().entrySet()) {
            if (!first) {
                json.append(',');
            }
            first = false;
            appendString(json, entry.getKey());
            json.append(':');
            if (entry.getValue() instanceof Long number) {
                json.append(number.longValue());
            } else {
                appendString(json, (String) entry.getValue());
            }
        }
        return json.append('}').toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void appendString(StringBuilder json, String value) {
        json.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\b' -> json.append("\\b");
                case '\f' -> json.append("\\f");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> {
                    if (c < 0x20) {
                        json.append(String.format("\\u%04x", (int) c));
                    } else {
                        json.append(c);
                    }
                }
            }
        }
        json.append('"');
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof FileManifest that && java.util.Arrays.equals(canonicalBytes(), that.canonicalBytes());
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(canonicalBytes());
    }

    @Override
    public String toString() {
        return "FileManifest[" + fileId + "]";
    }
}
