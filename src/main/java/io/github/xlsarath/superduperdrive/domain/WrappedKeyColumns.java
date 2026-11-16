package io.github.xlsarath.superduperdrive.domain;

import io.github.xlsarath.superduperdrive.crypto.kdf.Argon2Params;
import io.github.xlsarath.superduperdrive.crypto.keys.KeyWrapMethod;
import io.github.xlsarath.superduperdrive.crypto.keys.WrappedKeyBundle;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/** Column mapping of a {@link WrappedKeyBundle}; embedded twice in {@link UserAccount}. */
@Embeddable
public class WrappedKeyColumns {

    @Column(name = "method", length = 64)
    private String method;

    @Column(name = "salt")
    private byte[] salt;

    @Column(name = "argon2_memory_kib")
    private Integer argon2MemoryKib;

    @Column(name = "argon2_iterations")
    private Integer argon2Iterations;

    @Column(name = "argon2_parallelism")
    private Integer argon2Parallelism;

    @Column(name = "nonce")
    private byte[] nonce;

    @Column(name = "ciphertext")
    private byte[] ciphertext;

    protected WrappedKeyColumns() {
    }

    static WrappedKeyColumns of(WrappedKeyBundle bundle) {
        WrappedKeyColumns columns = new WrappedKeyColumns();
        columns.method = bundle.method().id();
        columns.salt = bundle.salt();
        if (bundle.argon2() != null) {
            columns.argon2MemoryKib = bundle.argon2().memoryKib();
            columns.argon2Iterations = bundle.argon2().iterations();
            columns.argon2Parallelism = bundle.argon2().parallelism();
        }
        columns.nonce = bundle.nonce();
        columns.ciphertext = bundle.ciphertext();
        return columns;
    }

    boolean isPresent() {
        return method != null && ciphertext != null;
    }

    WrappedKeyBundle toBundle() {
        Argon2Params argon2 = argon2MemoryKib == null ? null
                : new Argon2Params(argon2MemoryKib, argon2Iterations, argon2Parallelism);
        return new WrappedKeyBundle(KeyWrapMethod.fromId(method), salt, argon2, nonce, ciphertext);
    }
}
