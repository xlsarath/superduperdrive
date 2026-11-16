package io.github.xlsarath.superduperdrive.support;

import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.account.AccountService;
import io.github.xlsarath.superduperdrive.service.account.SignupCommand;
import io.github.xlsarath.superduperdrive.service.account.UnlockResult;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicInteger;

/** Creates signed-in test users through the real account service. Fake data only. */
@Component
public class TestUsers {

    public static final String PASSWORD = "ada-lovelace-1815";
    private static final AtomicInteger COUNTER = new AtomicInteger();

    private final AccountService accounts;
    private final UserAccountRepository users;

    public TestUsers(AccountService accounts, UserAccountRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    public static String uniqueUsername() {
        return "ada" + System.nanoTime() % 1_000_000 + "-" + COUNTER.incrementAndGet();
    }

    /** Registers a user and returns the recovery key. */
    public String register(String username) {
        return accounts.register(new SignupCommand("Ada", "Lovelace", username, PASSWORD.toCharArray()));
    }

    public ActiveUser signedIn() {
        String username = uniqueUsername();
        register(username);
        return unlock(username);
    }

    public ActiveUser unlock(String username) {
        var account = users.findByUsername(username).orElseThrow();
        UnlockResult result = accounts.unlock(account.getId(), PASSWORD.toCharArray());
        return new ActiveUser(account.getId(), username, result.keyring());
    }
}
