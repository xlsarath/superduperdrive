package io.github.xlsarath.superduperdrive.domain;

import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import io.github.xlsarath.superduperdrive.crypto.suite.ItemKind;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** A text note; title and body are both encrypted. */
@Entity
@Table(name = "note")
public class Note extends SealedItem {

    public static final String FIELD_TITLE = "title";
    public static final String FIELD_BODY = "body";

    @Column(name = "title_ciphertext", nullable = false)
    private byte[] titleCiphertext;

    @Column(name = "body_ciphertext", nullable = false)
    private byte[] bodyCiphertext;

    protected Note() {
    }

    public Note(UUID id, UUID ownerId) {
        super(id, ownerId, null);
    }

    @Override
    public ItemKind kind() {
        return ItemKind.NOTE;
    }

    public void seal(String suiteId, Envelope envelope, byte[] titleCiphertext, byte[] bodyCiphertext, Instant now) {
        applySeal(suiteId, envelope, now);
        this.titleCiphertext = titleCiphertext.clone();
        this.bodyCiphertext = bodyCiphertext.clone();
    }

    public byte[] getTitleCiphertext() {
        return titleCiphertext.clone();
    }

    public byte[] getBodyCiphertext() {
        return bodyCiphertext.clone();
    }
}
