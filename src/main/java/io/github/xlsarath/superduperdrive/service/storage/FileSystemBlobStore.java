package io.github.xlsarath.superduperdrive.service.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * {@link BlobStore} on the local file system. Layout: {@code <root>/<first two hex chars>/<key>.sdd}
 * for published blobs and {@code <root>/.pending/<key>.tmp} for writes in progress. Keys are
 * random UUIDs, validated on every access so no caller-supplied path can escape the root.
 */
public final class FileSystemBlobStore implements BlobStore {

    private static final Logger log = LoggerFactory.getLogger(FileSystemBlobStore.class);
    private static final Pattern KEY = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final String SUFFIX = ".sdd";
    private static final String PENDING_SUFFIX = ".tmp";

    private final Path root;
    private final Path pending;
    private final Clock clock;

    public FileSystemBlobStore(Path root, Clock clock) throws IOException {
        this.root = root.toAbsolutePath().normalize();
        this.pending = this.root.resolve(".pending");
        this.clock = clock;
        Files.createDirectories(pending);
    }

    @Override
    public PendingBlob begin() throws IOException {
        String key = UUID.randomUUID().toString();
        Path temp = pending.resolve(key + PENDING_SUFFIX);
        FileChannel channel = FileChannel.open(temp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return new FsPendingBlob(key, temp, channel, new SyncingOutputStream(channel));
    }

    @Override
    public InputStream open(String key) throws IOException {
        return Files.newInputStream(pathOf(key));
    }

    @Override
    public boolean delete(String key) throws IOException {
        return Files.deleteIfExists(pathOf(key));
    }

    @Override
    public int sweep(Duration minAge, Predicate<String> isReferenced) throws IOException {
        Instant cutoff = clock.instant().minus(minAge);
        int removed = 0;
        try (DirectoryStream<Path> temps = Files.newDirectoryStream(pending, "*" + PENDING_SUFFIX)) {
            for (Path temp : temps) {
                if (olderThan(temp, cutoff) && Files.deleteIfExists(temp)) {
                    removed++;
                }
            }
        }
        try (DirectoryStream<Path> shards = Files.newDirectoryStream(root, path -> Files.isDirectory(path)
                && path.getFileName().toString().matches("[0-9a-f]{2}"))) {
            for (Path shard : shards) {
                try (DirectoryStream<Path> blobs = Files.newDirectoryStream(shard, "*" + SUFFIX)) {
                    for (Path blob : blobs) {
                        String name = blob.getFileName().toString();
                        String key = name.substring(0, name.length() - SUFFIX.length());
                        if (KEY.matcher(key).matches() && olderThan(blob, cutoff) && !isReferenced.test(key)
                                && Files.deleteIfExists(blob)) {
                            log.info("Swept orphaned blob {}", key);
                            removed++;
                        }
                    }
                }
            }
        }
        return removed;
    }

    private static boolean olderThan(Path path, Instant cutoff) {
        try {
            return Files.getLastModifiedTime(path).toInstant().isBefore(cutoff);
        } catch (NoSuchFileException e) {
            return false;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Path pathOf(String key) {
        if (key == null || !KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("invalid blob key");
        }
        return root.resolve(key.substring(0, 2)).resolve(key + SUFFIX);
    }

    private final class FsPendingBlob implements PendingBlob {

        private final String key;
        private final Path temp;
        private final FileChannel channel;
        private final OutputStream out;
        private boolean published;

        FsPendingBlob(String key, Path temp, FileChannel channel, OutputStream out) {
            this.key = key;
            this.temp = temp;
            this.channel = channel;
            this.out = out;
        }

        @Override
        public String key() {
            return key;
        }

        @Override
        public OutputStream output() {
            return out;
        }

        @Override
        public void publish() throws IOException {
            // Durable before visible: flush and fsync (idempotent if the writer already closed
            // the stream), then atomically rename into place.
            out.close();
            channel.close();
            Path target = pathOf(key);
            Files.createDirectories(target.getParent());
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
            published = true;
        }

        @Override
        public void close() {
            if (published) {
                return;
            }
            try {
                channel.close();
            } catch (IOException e) {
                log.debug("Closing abandoned blob channel failed", e);
            }
            try {
                Files.deleteIfExists(temp);
            } catch (IOException e) {
                log.warn("Could not delete abandoned pending blob {}; the sweeper will retry", key, e);
            }
        }
    }

    /**
     * Buffered stream over the blob's channel whose {@code close()} flushes and fsyncs but leaves
     * the channel open, so writers may close it (as the encrypting stream does) before the blob
     * is published. The channel itself is closed by {@link FsPendingBlob}.
     */
    private static final class SyncingOutputStream extends OutputStream {

        private final FileChannel channel;
        private final BufferedOutputStream buffer;
        private boolean closed;

        SyncingOutputStream(FileChannel channel) {
            this.channel = channel;
            this.buffer = new BufferedOutputStream(Channels.newOutputStream(channel), 64 * 1024);
        }

        @Override
        public void write(int b) throws IOException {
            ensureOpen();
            buffer.write(b);
        }

        @Override
        public void write(byte[] bytes, int offset, int length) throws IOException {
            ensureOpen();
            buffer.write(bytes, offset, length);
        }

        @Override
        public void flush() throws IOException {
            ensureOpen();
            buffer.flush();
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            buffer.flush();
            channel.force(true);
        }

        private void ensureOpen() throws IOException {
            if (closed) {
                throw new IOException("blob stream is closed");
            }
        }
    }
}
