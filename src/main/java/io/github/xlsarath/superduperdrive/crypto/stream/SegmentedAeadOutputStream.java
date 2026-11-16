package io.github.xlsarath.superduperdrive.crypto.stream;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;
import io.github.xlsarath.superduperdrive.crypto.support.AesGcm;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * Encrypting side of {@link SegmentedAead}. A full segment is only emitted once the next byte
 * arrives, so that {@link #close()} always knows which segment is the last one.
 *
 * <p>{@link #close()} must be called to write the final segment; without it the output is
 * (detectably) truncated.
 */
public final class SegmentedAeadOutputStream extends FilterOutputStream {

    private final byte[] key;
    private final byte[] aad;
    private final byte[] noncePrefix;
    private final byte[] buffer;
    private int buffered;
    private long counter;
    private boolean closed;

    /**
     * @param sink         destination for the ciphertext
     * @param key          32-byte content key; copied, and the copy is wiped on close
     * @param streamAad    associated data identifying the item
     * @param segmentBytes plaintext bytes per segment
     */
    public SegmentedAeadOutputStream(OutputStream sink, byte[] key, byte[] streamAad, int segmentBytes,
                                     SecureRandom random) throws IOException {
        super(sink);
        SegmentedAead.checkSegmentSize(segmentBytes);
        this.key = Bytes.requireLength(key, AesGcm.KEY_BYTES, "content key").clone();
        this.noncePrefix = new byte[SegmentedAead.NONCE_PREFIX_BYTES];
        random.nextBytes(noncePrefix);
        byte[] header = ByteBuffer.allocate(SegmentedAead.HEADER_BYTES)
                .put(SegmentedAead.MAGIC)
                .put(SegmentedAead.VERSION)
                .putInt(segmentBytes)
                .put(noncePrefix)
                .array();
        this.aad = Bytes.concat(streamAad, header);
        this.buffer = new byte[segmentBytes];
        out.write(header);
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] data, int offset, int length) throws IOException {
        ensureOpen();
        while (length > 0) {
            if (buffered == buffer.length) {
                emit(false);
            }
            int chunk = Math.min(length, buffer.length - buffered);
            System.arraycopy(data, offset, buffer, buffered, chunk);
            buffered += chunk;
            offset += chunk;
            length -= chunk;
        }
    }

    @Override
    public void flush() throws IOException {
        // Segments are only written whole; flushing the sink is still useful for callers.
        out.flush();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        try {
            emit(true);
            out.flush();
        } finally {
            closed = true;
            Bytes.wipe(key, buffer);
            out.close();
        }
    }

    private void emit(boolean last) throws IOException {
        if (counter > SegmentedAead.MAX_SEGMENTS) {
            throw new CryptoException("stream exceeds the maximum number of segments");
        }
        byte[] plaintext = java.util.Arrays.copyOf(buffer, buffered);
        byte[] ciphertext = AesGcm.seal(key, SegmentedAead.nonce(noncePrefix, counter, last), aad, plaintext);
        Bytes.wipe(plaintext);
        out.write(ciphertext);
        counter++;
        buffered = 0;
    }

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("stream closed");
        }
    }
}
