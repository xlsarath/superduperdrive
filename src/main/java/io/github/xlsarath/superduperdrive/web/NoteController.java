package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.item.NoteService;
import io.github.xlsarath.superduperdrive.web.form.NoteForm;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/** Notes tab. */
@Controller
public class NoteController {

    private final NoteService notes;

    public NoteController(NoteService notes) {
        this.notes = notes;
    }

    @GetMapping("/notes")
    public String list(ActiveUser user, Model model) {
        model.addAttribute("notes", notes.list(user));
        model.addAttribute("active", "notes");
        return "notes";
    }

    @PostMapping("/notes")
    public String save(ActiveUser user, @Valid @ModelAttribute NoteForm form, BindingResult result,
                       RedirectAttributes redirect) {
        if (result.hasErrors()) {
            Flash.errors(redirect, result);
            return "redirect:/notes";
        }
        notes.save(user, form.getId(), form.getTitle(), form.getBody());
        Flash.success(redirect, form.getId() == null ? "Note encrypted and saved." : "Note updated and re-encrypted.");
        return "redirect:/notes";
    }

    @PostMapping("/notes/{id}/delete")
    public String delete(ActiveUser user, @PathVariable UUID id, RedirectAttributes redirect) {
        notes.delete(user, id);
        Flash.success(redirect, "Note deleted.");
        return "redirect:/notes";
    }
}
