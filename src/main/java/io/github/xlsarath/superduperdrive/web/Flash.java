package io.github.xlsarath.superduperdrive.web;

import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.stream.Collectors;

/** Post/redirect/get flash messages, rendered by the {@code flash} fragment. */
final class Flash {

    static final String SUCCESS = "flashSuccess";
    static final String ERROR = "flashError";

    private Flash() {
    }

    static void success(RedirectAttributes attributes, String message) {
        attributes.addFlashAttribute(SUCCESS, message);
    }

    static void error(RedirectAttributes attributes, String message) {
        attributes.addFlashAttribute(ERROR, message);
    }

    /** All validation messages of a binding result, as one sentence list. */
    static void errors(RedirectAttributes attributes, BindingResult result) {
        error(attributes, result.getAllErrors().stream()
                .map(ObjectError::getDefaultMessage)
                .distinct()
                .collect(Collectors.joining(" ")));
    }
}
