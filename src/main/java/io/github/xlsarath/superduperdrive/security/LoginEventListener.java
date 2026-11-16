package io.github.xlsarath.superduperdrive.security;

import io.github.xlsarath.superduperdrive.service.account.LoginAttemptService;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/** Feeds authentication events into the per-account lockout. */
@Component
public class LoginEventListener {

    private final LoginAttemptService loginAttempts;

    public LoginEventListener(LoginAttemptService loginAttempts) {
        this.loginAttempts = loginAttempts;
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        loginAttempts.recordFailure(event.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        loginAttempts.recordSuccess(event.getAuthentication().getName());
    }
}
