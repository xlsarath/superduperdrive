package io.github.xlsarath.superduperdrive.service.item;

import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;

import java.text.Normalizer;

/** Normalisation of user-supplied file names and media types. */
final class FileNames {

    static final int MAX_NAME_LENGTH = 255;
    static final String DEFAULT_TYPE = MediaType.APPLICATION_OCTET_STREAM_VALUE;

    private FileNames() {
    }

    /**
     * Keeps only the last path segment (some browsers send full client paths), normalises to
     * NFC, removes control and format characters, and trims.
     *
     * @throws InvalidUploadException if nothing usable remains
     */
    static String sanitize(String original) {
        if (original == null) {
            throw new InvalidUploadException("The file has no name.");
        }
        String name = original;
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        if (slash >= 0) {
            name = name.substring(slash + 1);
        }
        name = Normalizer.normalize(name, Normalizer.Form.NFC);
        StringBuilder clean = new StringBuilder(name.length());
        name.codePoints()
                .filter(cp -> !Character.isISOControl(cp) && Character.getType(cp) != Character.FORMAT)
                .forEach(clean::appendCodePoint);
        name = clean.toString().strip();
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            throw new InvalidUploadException("The file name is empty or invalid.");
        }
        if (name.length() > MAX_NAME_LENGTH) {
            throw new InvalidUploadException("The file name is longer than " + MAX_NAME_LENGTH + " characters.");
        }
        return name;
    }

    /** {@code type/subtype} without parameters, or {@code application/octet-stream} if unusable. */
    static String mediaType(String declared) {
        if (declared == null || declared.isBlank() || declared.length() > 255) {
            return DEFAULT_TYPE;
        }
        try {
            MediaType type = MediaType.parseMediaType(declared);
            if (type.isWildcardType() || type.isWildcardSubtype()) {
                return DEFAULT_TYPE;
            }
            return type.getType() + "/" + type.getSubtype();
        } catch (InvalidMediaTypeException e) {
            return DEFAULT_TYPE;
        }
    }
}
