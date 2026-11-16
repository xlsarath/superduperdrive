package io.github.xlsarath.superduperdrive.crypto.keys;

import io.github.xlsarath.superduperdrive.crypto.CryptoException;

import java.util.Arrays;

/** How a {@link WrappedKeyBundle} was protected. The id is persisted and bound into the AAD. */
public enum KeyWrapMethod {

    /** Key-encryption key = Argon2id(password, salt, params, ad = user id). */
    PASSWORD_ARGON2ID("PW-ARGON2ID-AES256GCM-v1"),

    /** Key-encryption key = HKDF-SHA-512(recovery key, salt, user id). Full-entropy input, so no stretching. */
    RECOVERY_KEY_HKDF("RK-HKDF-SHA512-AES256GCM-v1");

    private final String id;

    KeyWrapMethod(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public static KeyWrapMethod fromId(String id) {
        return Arrays.stream(values())
                .filter(method -> method.id.equals(id))
                .findFirst()
                .orElseThrow(() -> new CryptoException("unknown key wrap method"));
    }
}
