package io.github.xlsarath.superduperdrive.domain;

import io.github.xlsarath.superduperdrive.crypto.suite.Envelope;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/** Column mapping of a crypto {@link Envelope}. */
@Embeddable
public class EnvelopeColumns {

    @Column(name = "envelope_version")
    private Integer formatVersion;

    @Column(name = "kem_ciphertext")
    private byte[] kemCiphertext;

    @Column(name = "wrap_nonce")
    private byte[] wrapNonce;

    @Column(name = "wrapped_dek")
    private byte[] wrappedDek;

    protected EnvelopeColumns() {
    }

    static EnvelopeColumns of(Envelope envelope) {
        EnvelopeColumns columns = new EnvelopeColumns();
        columns.formatVersion = envelope.formatVersion();
        columns.kemCiphertext = envelope.kemCiphertext();
        columns.wrapNonce = envelope.wrapNonce();
        columns.wrappedDek = envelope.wrappedDek();
        return columns;
    }

    boolean isPresent() {
        return formatVersion != null && kemCiphertext != null && wrapNonce != null && wrappedDek != null;
    }

    Envelope toEnvelope() {
        return new Envelope(formatVersion, kemCiphertext, wrapNonce, wrappedDek);
    }
}
