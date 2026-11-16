package io.github.xlsarath.superduperdrive.service.item;

/** The upload is empty or its name is unusable. The message is safe to show to the user. */
public class InvalidUploadException extends RuntimeException {

    public InvalidUploadException(String message) {
        super(message);
    }
}
