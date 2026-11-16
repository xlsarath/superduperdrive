package io.github.xlsarath.superduperdrive.web.form;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Sign-up form. The password protects the private keys, hence the 12-character minimum. */
public class SignupForm {

    @NotBlank(message = "Enter your first name.")
    @Size(max = 64, message = "First name must be at most 64 characters.")
    private String firstName;

    @NotBlank(message = "Enter your last name.")
    @Size(max = 64, message = "Last name must be at most 64 characters.")
    private String lastName;

    @Pattern(regexp = "^[A-Za-z0-9._-]{3,32}$",
            message = "Use 3 to 32 letters, digits, dots, dashes or underscores.")
    private String username;

    @Size(min = 12, max = 128, message = "Use 12 to 128 characters; a passphrase is ideal.")
    private String password;

    private String confirmPassword;

    @AssertTrue(message = "The passwords do not match.")
    public boolean isPasswordConfirmed() {
        return password != null && password.equals(confirmPassword);
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    /** Drops the passwords so they are not echoed back into a re-rendered form. */
    public void clearPasswords() {
        password = null;
        confirmPassword = null;
    }

    @Override
    public String toString() {
        return "SignupForm[username=" + username + "]";
    }
}
