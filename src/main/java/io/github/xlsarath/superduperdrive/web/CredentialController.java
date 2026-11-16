package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.item.CredentialService;
import io.github.xlsarath.superduperdrive.web.form.CredentialForm;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;
import java.util.UUID;

/** Credentials tab. Passwords are only decrypted on an explicit, CSRF-protected reveal. */
@Controller
public class CredentialController {

    private final CredentialService credentials;

    public CredentialController(CredentialService credentials) {
        this.credentials = credentials;
    }

    @GetMapping("/credentials")
    public String list(ActiveUser user, Model model) {
        model.addAttribute("credentials", credentials.list(user));
        model.addAttribute("active", "credentials");
        return "credentials";
    }

    @PostMapping("/credentials")
    public String save(ActiveUser user, @Valid @ModelAttribute CredentialForm form, BindingResult result,
                       RedirectAttributes redirect) {
        if (result.hasErrors()) {
            Flash.errors(redirect, result);
            return "redirect:/credentials";
        }
        credentials.save(user, form.getId(), form.getUrl().strip(), form.getUsername(), form.getPassword());
        Flash.success(redirect, form.getId() == null ? "Credential encrypted and saved."
                : "Credential updated and re-encrypted.");
        return "redirect:/credentials";
    }

    @PostMapping("/credentials/{id}/reveal")
    public ResponseEntity<Map<String, String>> reveal(ActiveUser user, @PathVariable UUID id) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(Map.of("password", credentials.reveal(user, id)));
    }

    @PostMapping("/credentials/{id}/delete")
    public String delete(ActiveUser user, @PathVariable UUID id, RedirectAttributes redirect) {
        credentials.delete(user, id);
        Flash.success(redirect, "Credential deleted.");
        return "redirect:/credentials";
    }
}
