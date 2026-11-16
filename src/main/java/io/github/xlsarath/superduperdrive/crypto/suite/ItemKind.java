package io.github.xlsarath.superduperdrive.crypto.suite;

/** Kinds of user items. The code is bound into every item's associated data. */
public enum ItemKind {
    FILE("file"),
    NOTE("note"),
    CREDENTIAL("credential");

    private final String code;

    ItemKind(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}
