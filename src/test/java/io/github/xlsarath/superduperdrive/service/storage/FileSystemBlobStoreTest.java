package io.github.xlsarath.superduperdrive.service.storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FileSystemBlobStoreTest {

    @TempDir
    Path root;

    @Test
    void pendingBlobsBecomeVisibleOnlyWhenPublished() throws IOException {
        FileSystemBlobStore store = new FileSystemBlobStore(root, Clock.systemUTC());
        String key;
        try (BlobStore.PendingBlob blob = store.begin()) {
            key = blob.key();
            blob.output().write(new byte[] {1, 2, 3});
            assertThatThrownBy(() -> store.open(blob.key()).close()).isInstanceOf(IOException.class);
            blob.publish();
        }
        try (InputStream in = store.open(key)) {
            assertThat(in.readAllBytes()).containsExactly(1, 2, 3);
        }
        assertThat(store.delete(key)).isTrue();
        assertThat(store.delete(key)).isFalse();
    }

    @Test
    void writersMayCloseTheStreamBeforePublishing() throws IOException {
        FileSystemBlobStore store = new FileSystemBlobStore(root, Clock.systemUTC());
        String key;
        try (BlobStore.PendingBlob blob = store.begin()) {
            key = blob.key();
            blob.output().write(new byte[] {4, 5});
            blob.output().close(); // e.g. an encrypting stream closing its sink
            assertThatThrownBy(() -> blob.output().write(6)).isInstanceOf(IOException.class);
            blob.publish();
        }
        try (InputStream in = store.open(key)) {
            assertThat(in.readAllBytes()).containsExactly(4, 5);
        }
    }

    @Test
    void abandonedWritesAreDiscarded() throws IOException {
        FileSystemBlobStore store = new FileSystemBlobStore(root, Clock.systemUTC());
        try (BlobStore.PendingBlob blob = store.begin()) {
            blob.output().write(42);
        }
        try (Stream<Path> pending = Files.list(root.resolve(".pending"))) {
            assertThat(pending).isEmpty();
        }
    }

    @Test
    void rejectsKeysThatCouldEscapeTheRoot() throws IOException {
        FileSystemBlobStore store = new FileSystemBlobStore(root, Clock.systemUTC());
        assertThatThrownBy(() -> store.open("../../etc/passwd")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.delete("ab")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sweepRemovesOldUnreferencedBlobsOnly() throws IOException {
        FileSystemBlobStore store = new FileSystemBlobStore(root, Clock.systemUTC());
        String referenced = publish(store);
        String orphan = publish(store);
        String fresh = publish(store);
        FileTime old = FileTime.from(Instant.now().minus(Duration.ofHours(2)));
        for (String key : new String[] {referenced, orphan}) {
            Files.setLastModifiedTime(root.resolve(key.substring(0, 2)).resolve(key + ".sdd"), old);
        }
        int removed = store.sweep(Duration.ofHours(1), key -> key.equals(referenced));
        assertThat(removed).isEqualTo(1);
        store.open(referenced).close();
        store.open(fresh).close();
        assertThatThrownBy(() -> store.open(orphan).close()).isInstanceOf(IOException.class);
    }

    private static String publish(FileSystemBlobStore store) throws IOException {
        try (BlobStore.PendingBlob blob = store.begin()) {
            blob.output().write(7);
            blob.publish();
            return blob.key();
        }
    }
}
