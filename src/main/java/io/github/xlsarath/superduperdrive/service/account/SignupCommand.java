package io.github.xlsarath.superduperdrive.service.account;

/** Input for {@link AccountService#register}. The password is wiped by the service. */
public record SignupCommand(String firstName, String lastName, String username, char[] password) {

    @Override
    public String toString() {
        return "SignupCommand[username=" + username + "]";
    }
}
