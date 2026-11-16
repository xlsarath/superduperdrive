package io.github.xlsarath.superduperdrive.service.item;

/** The user already has a file with this name (compared case-insensitively). */
public class DuplicateFileNameException extends RuntimeException {

    public DuplicateFileNameException() {
        super("a file with this name already exists");
    }
}
