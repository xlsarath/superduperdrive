package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.item.CryptoMigrationService;
import io.github.xlsarath.superduperdrive.service.item.SecurityOverviewService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/** Security tab: keys, suites, per-item status, re-key actions. */
@Controller
public class SecurityController {

    private final SecurityOverviewService overview;
    private final CryptoMigrationService migration;

    public SecurityController(SecurityOverviewService overview, CryptoMigrationService migration) {
        this.overview = overview;
        this.migration = migration;
    }

    @GetMapping("/security")
    public String security(ActiveUser user, Model model) {
        model.addAttribute("overview", overview.overview(user));
        model.addAttribute("active", "security");
        return "security";
    }

    @PostMapping("/security/rekey")
    public String rekey(ActiveUser user, @RequestParam ItemKind kind, @RequestParam UUID id,
                        RedirectAttributes redirect) {
        migration.rekey(user, kind, id);
        Flash.success(redirect, "Re-keyed with a fresh data key and a fresh hybrid encapsulation.");
        return "redirect:/security";
    }

    @PostMapping("/security/migrate")
    public String migrateAll(ActiveUser user, RedirectAttributes redirect) {
        CryptoMigrationService.MigrationReport report = migration.migrateOutdatedItems(user);
        if (report.failed() > 0) {
            Flash.error(redirect, report.migrated() + " item(s) migrated, " + report.failed()
                    + " failed. Details are in the server log.");
        } else {
            Flash.success(redirect, report.migrated() == 0 ? "Everything already uses the current suite."
                    : report.migrated() + " item(s) migrated to the current suite.");
        }
        return "redirect:/security";
    }
}
