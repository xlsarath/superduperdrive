package io.github.xlsarath.superduperdrive.service.account;

public class UsernameTakenException extends RuntimeException {

    public UsernameTakenException() {
        super("username is already taken");
    }
}
