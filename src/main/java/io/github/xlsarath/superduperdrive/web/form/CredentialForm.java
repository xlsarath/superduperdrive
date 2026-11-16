package io.github.xlsarath.superduperdrive.web.form;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

/**
 * Create or edit a credential. When editing, an empty password keeps the stored one, so the
 * edit dialog never has to contain the plaintext.
 */
public class CredentialForm {

    private UUID id;

    @NotBlank(message = "Enter the site address.")
    @Size(max = 2048, message = "The address must be at most 2048 characters.")
    @Pattern(regexp = "^\\S+$", message = "The address must not contain spaces.")
    private String url;

    @NotBlank(message = "Enter the username for the site.")
    @Size(max = 256, message = "The username must be at most 256 characters.")
    private String username;

    @Size(max = 1024, message = "The password must be at most 1024 characters.")
    private String password;

    @AssertTrue(message = "Enter a password for the new credential.")
    public boolean isPasswordPresentWhenCreating() {
        return id != null || (password != null && !password.isEmpty());
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
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

    @Override
    public String toString() {
        return "CredentialForm[id=" + id + "]";
    }
}
