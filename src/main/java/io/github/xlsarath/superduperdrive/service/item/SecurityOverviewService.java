package io.github.xlsarath.superduperdrive.service.item;

import io.github.xlsarath.superduperdrive.crypto.suite.CryptoSuiteRegistry;
import io.github.xlsarath.superduperdrive.crypto.keys.WrappedKeyBundle;
import io.github.xlsarath.superduperdrive.domain.UserAccount;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.KeysLockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/** Assembles the Security page: key fingerprints, suite registry and per-item status. */
@Service
public class SecurityOverviewService {

    private final UserAccountRepository users;
    private final CryptoSuiteRegistry registry;
    private final CryptoMigrationService migration;

    public SecurityOverviewService(UserAccountRepository users, CryptoSuiteRegistry registry,
                                   CryptoMigrationService migration) {
        this.users = users;
        this.registry = registry;
        this.migration = migration;
    }

    @Transactional(readOnly = true)
    public SecurityOverview overview(ActiveUser user) {
        UserAccount account = users.findById(user.id()).orElseThrow(KeysLockedException::new);
        List<SecurityItemView> items = new ArrayList<>();
        migration.handlers().values().forEach(handler -> items.addAll(handler.describe(user)));
        var publicKeys = user.keyring().publicKeys();
        String keyWrap = account.passwordWrappedKeys().map(WrappedKeyBundle::describe).orElse("not provisioned");
        String keyWrapMethod = account.passwordWrappedKeys().map(bundle -> bundle.method().id()).orElse("");
        return new SecurityOverview(account.getKeySuite(), publicKeys.encryptionKeyFingerprint(),
                publicKeys.signingKeyFingerprint(), keyWrap, keyWrapMethod, account.getKeysCreatedAt(),
                account.getRecoveryKeyIssuedAt(), registry.descriptors(), List.copyOf(items));
    }
}
