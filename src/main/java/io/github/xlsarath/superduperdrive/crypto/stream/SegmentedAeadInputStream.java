package io.github.xlsarath.superduperdrive.crypto.stream;

import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import io.github.xlsarath.superduperdrive.crypto.support.AesGcm;
import io.github.xlsarath.superduperdrive.crypto.support.Bytes;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Decrypting side of {@link SegmentedAead}. Plaintext is released one fully authenticated
 * segment at a time. Any tampering, reordering, truncation or trailing data raises
 * {@link IntegrityException} (an unchecked exception, so it also escapes {@code read} calls
 * made by generic copy utilities).
 */
public final class SegmentedAeadInputStream extends InputStream {

    private final PushbackInputStream source;
    private final byte[] key;
    private final byte[] streamAad;
    private byte[] aad;
    private byte[] noncePrefix;
    private int segmentBytes;
    private byte[] plaintext = new byte[0];
    private int position;
    private long counter;
    private boolean finished;
    private boolean closed;

    public SegmentedAeadInputStream(InputStream source, byte[] key, byte[] streamAad) {
        this.source = new PushbackInputStream(source, 1);
        this.key = Bytes.requireLength(key, AesGcm.KEY_BYTES, "content key").clone();
        this.streamAad = streamAad.clone();
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int n = read(one, 0, 1);
        return n < 0 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(byte[] target, int offset, int length) throws IOException {
        if (closed) {
            throw new IOException("stream closed");
        }
        if (length == 0) {
            return 0;
        }
        while (position == plaintext.length) {
            if (finished) {
                return -1;
            }
            nextSegment();
        }
        int n = Math.min(length, plaintext.length - position);
        System.arraycopy(plaintext, position, target, offset, n);
        position += n;
        return n;
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
            Bytes.wipe(key, plaintext);
            source.close();
        }
    }

    private void nextSegment() throws IOException {
        if (aad == null) {
            readHeader();
        }
        if (counter > SegmentedAead.MAX_SEGMENTS) {
            throw new IntegrityException("stream has too many segments");
        }
        byte[] segment = source.readNBytes(segmentBytes + AesGcm.TAG_BYTES);
        if (segment.length < AesGcm.TAG_BYTES) {
            throw new IntegrityException("stream truncated");
        }
        int next = source.read();
        boolean last = next < 0;
        if (!last) {
            source.unread(next);
            if (segment.length != segmentBytes + AesGcm.TAG_BYTES) {
                throw new IntegrityException("short non-final segment");
            }
        }
        byte[] decrypted = AesGcm.open(key, SegmentedAead.nonce(noncePrefix, counter, last), aad, segment);
        Bytes.wipe(plaintext);
        plaintext = decrypted;
        position = 0;
        counter++;
        finished = last;
    }

    private void readHeader() throws IOException {
        byte[] header = source.readNBytes(SegmentedAead.HEADER_BYTES);
        if (header.length != SegmentedAead.HEADER_BYTES) {
            throw new IntegrityException("stream header truncated");
        }
        ByteBuffer view = ByteBuffer.wrap(header);
        byte[] magic = new byte[SegmentedAead.MAGIC.length];
        view.get(magic);
        byte version = view.get();
        int declaredSegment = view.getInt();
        if (!Arrays.equals(magic, SegmentedAead.MAGIC) || version != SegmentedAead.VERSION
                || declaredSegment < SegmentedAead.MIN_SEGMENT_BYTES
                || declaredSegment > SegmentedAead.MAX_SEGMENT_BYTES) {
            throw new IntegrityException("unrecognised stream header");
        }
        this.segmentBytes = declaredSegment;
        this.noncePrefix = new byte[SegmentedAead.NONCE_PREFIX_BYTES];
        view.get(noncePrefix);
        this.aad = Bytes.concat(streamAad, header);
    }
}
