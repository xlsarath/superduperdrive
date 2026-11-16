package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.crypto.IntegrityException;
import io.github.xlsarath.superduperdrive.service.ItemNotFoundException;
import io.github.xlsarath.superduperdrive.service.KeysLockedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/** Maps domain exceptions to pages; no stack traces or internals reach the browser. */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** Unknown ids, other users' ids and malformed ids all look the same: 404. */
    @ExceptionHandler({ItemNotFoundException.class, MethodArgumentTypeMismatchException.class})
    public String notFound(Exception e, HttpServletResponse response, Model model) {
        log.info("Not found: {}", e.getMessage());
        return error(response, model, HttpStatus.NOT_FOUND, "Not found",
                "That item does not exist or is not yours.");
    }

    @ExceptionHandler(IntegrityException.class)
    public String integrity(IntegrityException e, HttpServletResponse response, Model model) {
        log.error("Integrity check failed: {}", e.getMessage());
        return error(response, model, HttpStatus.CONFLICT, "Integrity check failed",
                "The stored data did not pass its authenticity check, so it was not released. "
                        + "It may have been modified outside the application.");
    }

    @ExceptionHandler(KeysLockedException.class)
    public String keysLocked(HttpServletRequest request, HttpServletResponse response) {
        log.info("Session has no unlocked keys; signing out");
        new SecurityContextLogoutHandler().logout(request, response,
                SecurityContextHolder.getContext().getAuthentication());
        return "redirect:/login?expired";
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public String tooLarge(MaxUploadSizeExceededException e, RedirectAttributes redirect) {
        log.info("Rejected an upload over the size limit");
        Flash.error(redirect, "That file is larger than the upload limit.");
        return "redirect:/files";
    }

    private static String error(HttpServletResponse response, Model model, HttpStatus status, String title,
                                String message) {
        response.setStatus(status.value());
        model.addAttribute("status", status.value());
        model.addAttribute("title", title);
        model.addAttribute("message", message);
        return "error";
    }
}
