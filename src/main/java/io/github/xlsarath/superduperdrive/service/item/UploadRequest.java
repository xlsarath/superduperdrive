package io.github.xlsarath.superduperdrive.service.item;

import org.springframework.core.io.InputStreamSource;

/** A file to store, independent of the web layer's multipart type. */
public record UploadRequest(String originalFilename, String contentType, InputStreamSource content) {
}
