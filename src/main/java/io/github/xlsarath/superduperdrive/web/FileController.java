package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.item.DuplicateFileNameException;
import io.github.xlsarath.superduperdrive.service.item.FileDownload;
import io.github.xlsarath.superduperdrive.service.item.FileService;
import io.github.xlsarath.superduperdrive.service.item.InvalidUploadException;
import io.github.xlsarath.superduperdrive.service.item.SignedManifest;
import io.github.xlsarath.superduperdrive.service.item.UploadRequest;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Files tab: list, upload, verified download, signed manifest export, delete. */
@Controller
public class FileController {

    /** Download responses may not run anything: belt and braces on top of the attachment disposition. */
    private static final String DOWNLOAD_CSP = "sandbox; default-src 'none'";

    private final FileService files;

    public FileController(FileService files) {
        this.files = files;
    }

    @GetMapping("/files")
    public String list(ActiveUser user, Model model) {
        model.addAttribute("files", files.list(user));
        model.addAttribute("active", "files");
        return "files";
    }

    @PostMapping("/files")
    public String upload(ActiveUser user, @RequestParam("file") MultipartFile file, RedirectAttributes redirect)
            throws IOException {
        if (file == null || file.isEmpty()) {
            Flash.error(redirect, "Choose a non-empty file to upload.");
            return "redirect:/files";
        }
        try {
            files.upload(user, new UploadRequest(file.getOriginalFilename(), file.getContentType(), file));
            Flash.success(redirect, "Encrypted, signed and stored.");
        } catch (DuplicateFileNameException e) {
            Flash.error(redirect, "You already have a file with that name. Rename it or delete the old one first.");
        } catch (InvalidUploadException e) {
            Flash.error(redirect, e.getMessage());
        }
        return "redirect:/files";
    }

    /**
     * Streams a verified file as an opaque attachment: {@code application/octet-stream},
     * {@code Content-Disposition: attachment}, {@code nosniff} (set globally) and a sandbox CSP,
     * so a browser never renders or executes uploaded content in this origin.
     */
    @GetMapping("/files/{id}/download")
    public ResponseEntity<StreamingResponseBody> download(ActiveUser user, @PathVariable UUID id) throws IOException {
        FileDownload download = files.download(user, id);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(download.size())
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(download.fileName(), StandardCharsets.UTF_8).build().toString())
                .header("Content-Security-Policy", DOWNLOAD_CSP)
                .body(out -> download.content().writeTo(out));
    }

    @GetMapping(value = "/files/{id}/manifest")
    public ResponseEntity<SignedManifest> manifest(ActiveUser user, @PathVariable UUID id) {
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(id + ".manifest.json").build().toString())
                .body(files.signedManifest(user, id));
    }

    @PostMapping("/files/{id}/delete")
    public String delete(ActiveUser user, @PathVariable UUID id, RedirectAttributes redirect) {
        files.delete(user, id);
        Flash.success(redirect, "File deleted.");
        return "redirect:/files";
    }
}
