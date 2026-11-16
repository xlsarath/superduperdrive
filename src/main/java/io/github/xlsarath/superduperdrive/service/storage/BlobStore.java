package io.github.xlsarath.superduperdrive.service.storage;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Duration;
import java.util.function.Predicate;

/**
 * Storage for encrypted file content. Blobs are opaque ciphertext; the store never sees keys.
 *
 * <p>Writes are two-phase: {@link #begin()} returns a {@link PendingBlob} that is invisible
 * until {@link PendingBlob#publish()}, so a failed upload never leaves a half-written blob
 * under a key that a database row could reference.
 */
public interface BlobStore {

    PendingBlob begin() throws IOException;

    InputStream open(String key) throws IOException;

    /** Deletes the blob if present; returns whether something was deleted. */
    boolean delete(String key) throws IOException;

    /**
     * Deletes published blobs older than {@code minAge} for which {@code isReferenced} is false,
     * and abandoned pending writes older than {@code minAge}. Returns the number removed.
     */
    int sweep(Duration minAge, Predicate<String> isReferenced) throws IOException;

    /** An in-progress write. Close the {@link #output()} stream before publishing. */
    interface PendingBlob extends AutoCloseable {

        String key();

        OutputStream output();

        /** Atomically makes the blob readable under {@link #key()}. */
        void publish() throws IOException;

        /** Discards the write if it was not published. Idempotent. */
        @Override
        void close();
    }
}
