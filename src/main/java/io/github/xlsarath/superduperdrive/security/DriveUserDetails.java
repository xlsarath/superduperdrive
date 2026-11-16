package io.github.xlsarath.superduperdrive.security;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/** Spring Security principal carrying the account id. The password hash is erased after login. */
public final class DriveUserDetails implements UserDetails, CredentialsContainer {

    private static final List<GrantedAuthority> AUTHORITIES = AuthorityUtils.createAuthorityList("ROLE_USER");

    private final UUID id;
    private final String username;
    private final boolean accountNonLocked;
    private String passwordHash;

    public DriveUserDetails(UUID id, String username, String passwordHash, boolean accountNonLocked) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.accountNonLocked = accountNonLocked;
    }

    public UUID id() {
        return id;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return AUTHORITIES;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public void eraseCredentials() {
        passwordHash = null;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof DriveUserDetails that && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return "DriveUserDetails[" + id + "]";
    }
}
