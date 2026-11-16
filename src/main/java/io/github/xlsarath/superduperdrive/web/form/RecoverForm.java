package io.github.xlsarath.superduperdrive.web.form;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Account recovery: username, recovery key and a new password. */
public class RecoverForm {

    @NotBlank(message = "Enter your username.")
    @Size(max = 32)
    private String username;

    @NotBlank(message = "Enter your recovery key.")
    @Size(max = 128, message = "That does not look like a recovery key.")
    private String recoveryKey;

    @Size(min = 12, max = 128, message = "Use 12 to 128 characters; a passphrase is ideal.")
    private String newPassword;

    private String confirmPassword;

    @AssertTrue(message = "The passwords do not match.")
    public boolean isPasswordConfirmed() {
        return newPassword != null && newPassword.equals(confirmPassword);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRecoveryKey() {
        return recoveryKey;
    }

    public void setRecoveryKey(String recoveryKey) {
        this.recoveryKey = recoveryKey;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public void clearSecrets() {
        recoveryKey = null;
        newPassword = null;
        confirmPassword = null;
    }

    @Override
    public String toString() {
        return "RecoverForm[username=" + username + "]";
    }
}
