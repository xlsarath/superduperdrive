package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.security.KeyUnlockingSuccessHandler;
import io.github.xlsarath.superduperdrive.service.account.AccountService;
import io.github.xlsarath.superduperdrive.service.account.RecoveryFailedException;
import io.github.xlsarath.superduperdrive.service.account.SignupCommand;
import io.github.xlsarath.superduperdrive.service.account.UsernameTakenException;
import io.github.xlsarath.superduperdrive.web.form.RecoverForm;
import io.github.xlsarath.superduperdrive.web.form.SignupForm;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/** Login page, sign-up, account recovery and the one-time recovery-key page. */
@Controller
public class AuthController {

    private static final String RECOVERY_KEY_VIEW = "recovery-key";

    private final AccountService accounts;

    public AuthController(AccountService accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/signup")
    public String signupForm(@ModelAttribute("form") SignupForm form) {
        return "signup";
    }

    /** Renders the recovery key directly in the response; it is never stored in plaintext. */
    @PostMapping("/signup")
    public String signup(@Valid @ModelAttribute("form") SignupForm form, BindingResult result, Model model) {
        if (result.hasErrors()) {
            form.clearPasswords();
            return "signup";
        }
        try {
            String recoveryKey = accounts.register(new SignupCommand(form.getFirstName(), form.getLastName(),
                    form.getUsername(), form.getPassword().toCharArray()));
            model.addAttribute("recoveryKey", recoveryKey);
            model.addAttribute("context", "signup");
            return RECOVERY_KEY_VIEW;
        } catch (UsernameTakenException e) {
            result.rejectValue("username", "taken", "That username is already taken.");
            form.clearPasswords();
            return "signup";
        }
    }

    @GetMapping("/recover")
    public String recoverForm(@ModelAttribute("form") RecoverForm form) {
        return "recover";
    }

    @PostMapping("/recover")
    public String recover(@Valid @ModelAttribute("form") RecoverForm form, BindingResult result, Model model) {
        if (result.hasErrors()) {
            form.clearSecrets();
            return "recover";
        }
        try {
            String recoveryKey = accounts.recover(form.getUsername(), form.getRecoveryKey(),
                    form.getNewPassword().toCharArray());
            model.addAttribute("recoveryKey", recoveryKey);
            model.addAttribute("context", "recovery");
            return RECOVERY_KEY_VIEW;
        } catch (RecoveryFailedException e) {
            form.clearSecrets();
            model.addAttribute("recoveryFailed", true);
            return "recover";
        }
    }

    /** Shows a recovery key issued during login (accounts migrated from the 2020 schema), once. */
    @GetMapping("/account/recovery-key")
    public String pendingRecoveryKey(HttpSession session, Model model) {
        Object pending = session.getAttribute(KeyUnlockingSuccessHandler.PENDING_RECOVERY_KEY);
        session.removeAttribute(KeyUnlockingSuccessHandler.PENDING_RECOVERY_KEY);
        if (!(pending instanceof String recoveryKey)) {
            return "redirect:/files";
        }
        model.addAttribute("recoveryKey", recoveryKey);
        model.addAttribute("context", "upgrade");
        return RECOVERY_KEY_VIEW;
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/files";
    }
}
