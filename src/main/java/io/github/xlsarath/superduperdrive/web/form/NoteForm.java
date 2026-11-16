package io.github.xlsarath.superduperdrive.web.form;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

/** Create or edit a note; {@code id} is empty for a new note. */
public class NoteForm {

    private UUID id;

    @NotBlank(message = "A note needs a title.")
    @Size(max = 120, message = "The title must be at most 120 characters.")
    private String title;

    @NotNull
    @Size(max = 10_000, message = "The note must be at most 10,000 characters.")
    private String body = "";

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
