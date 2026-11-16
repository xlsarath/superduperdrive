package io.github.xlsarath.superduperdrive.service.item;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A verified file ready to stream. {@link #writeTo} decrypts segment by segment straight into
 * the response and releases the data key when done.
 */
public record FileDownload(String fileName, long size, ContentWriter content) {

    @FunctionalInterface
    public interface ContentWriter {
        void writeTo(OutputStream out) throws IOException;
    }
}
