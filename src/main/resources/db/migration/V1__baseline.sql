-- SuperDuperDrive schema, version 2 of the application.
-- Portable between PostgreSQL and H2 (which runs in PostgreSQL compatibility mode).
-- Every user-content column is ciphertext; see docs/CRYPTO.md for the formats.

CREATE TABLE user_account (
    id                          UUID                     NOT NULL,
    username                    VARCHAR(32)              NOT NULL,
    password_hash               VARCHAR(512)             NOT NULL,
    first_name                  VARCHAR(64)              NOT NULL,
    last_name                   VARCHAR(64)              NOT NULL,
    failed_login_attempts       INTEGER                  NOT NULL DEFAULT 0,
    locked_until                TIMESTAMP WITH TIME ZONE,
    -- Public keys (NULL for accounts created before key provisioning).
    key_suite                   VARCHAR(64),
    x25519_public_key           BYTEA,
    ml_kem_public_key           BYTEA,
    ml_dsa_public_key           BYTEA,
    keys_created_at             TIMESTAMP WITH TIME ZONE,
    -- Private keys wrapped under an Argon2id password-derived key.
    pw_wrap_method              VARCHAR(64),
    pw_wrap_salt                BYTEA,
    pw_wrap_argon2_memory_kib   INTEGER,
    pw_wrap_argon2_iterations   INTEGER,
    pw_wrap_argon2_parallelism  INTEGER,
    pw_wrap_nonce               BYTEA,
    pw_wrap_ciphertext          BYTEA,
    -- Second copy of the private keys wrapped under the user-held recovery key.
    rk_wrap_method              VARCHAR(64),
    rk_wrap_salt                BYTEA,
    rk_wrap_argon2_memory_kib   INTEGER,
    rk_wrap_argon2_iterations   INTEGER,
    rk_wrap_argon2_parallelism  INTEGER,
    rk_wrap_nonce               BYTEA,
    rk_wrap_ciphertext          BYTEA,
    recovery_key_issued_at      TIMESTAMP WITH TIME ZONE,
    created_at                  TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at                  TIMESTAMP WITH TIME ZONE NOT NULL,
    version                     BIGINT                   NOT NULL,
    CONSTRAINT pk_user_account PRIMARY KEY (id),
    CONSTRAINT uk_user_account_username UNIQUE (username),
    CONSTRAINT ck_user_account_failed_attempts CHECK (failed_login_attempts >= 0)
);

CREATE TABLE note (
    id                    UUID                     NOT NULL,
    owner_id              UUID                     NOT NULL,
    suite_id              VARCHAR(64)              NOT NULL,
    envelope_version      INTEGER,
    kem_ciphertext        BYTEA,
    wrap_nonce            BYTEA,
    wrapped_dek           BYTEA,
    sealed_at             TIMESTAMP WITH TIME ZONE,
    migrated_from_suite   VARCHAR(64),
    title_ciphertext      BYTEA                    NOT NULL,
    body_ciphertext       BYTEA                    NOT NULL,
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL,
    version               BIGINT                   NOT NULL,
    CONSTRAINT pk_note PRIMARY KEY (id),
    CONSTRAINT fk_note_owner FOREIGN KEY (owner_id) REFERENCES user_account (id) ON DELETE CASCADE
);
CREATE INDEX ix_note_owner ON note (owner_id);

CREATE TABLE credential (
    id                    UUID                     NOT NULL,
    owner_id              UUID                     NOT NULL,
    suite_id              VARCHAR(64)              NOT NULL,
    envelope_version      INTEGER,
    kem_ciphertext        BYTEA,
    wrap_nonce            BYTEA,
    wrapped_dek           BYTEA,
    sealed_at             TIMESTAMP WITH TIME ZONE,
    migrated_from_suite   VARCHAR(64),
    url_ciphertext        BYTEA,
    username_ciphertext   BYTEA,
    password_ciphertext   BYTEA,
    -- Columns of the 2020 schema; only populated for rows awaiting migration.
    legacy_url            VARCHAR(2048),
    legacy_username       VARCHAR(256),
    legacy_key            VARCHAR(64),
    legacy_password       VARCHAR(4096),
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL,
    version               BIGINT                   NOT NULL,
    CONSTRAINT pk_credential PRIMARY KEY (id),
    CONSTRAINT fk_credential_owner FOREIGN KEY (owner_id) REFERENCES user_account (id) ON DELETE CASCADE,
    CONSTRAINT ck_credential_sealed_or_legacy CHECK (
        (password_ciphertext IS NOT NULL AND legacy_password IS NULL)
        OR (password_ciphertext IS NULL AND legacy_password IS NOT NULL AND legacy_key IS NOT NULL))
);
CREATE INDEX ix_credential_owner ON credential (owner_id);

CREATE TABLE stored_file (
    id                        UUID                     NOT NULL,
    owner_id                  UUID                     NOT NULL,
    suite_id                  VARCHAR(64)              NOT NULL,
    envelope_version          INTEGER,
    kem_ciphertext            BYTEA,
    wrap_nonce                BYTEA,
    wrapped_dek               BYTEA,
    sealed_at                 TIMESTAMP WITH TIME ZONE,
    migrated_from_suite       VARCHAR(64),
    name_ciphertext           BYTEA                    NOT NULL,
    content_type_ciphertext   BYTEA                    NOT NULL,
    digest_ciphertext         BYTEA                    NOT NULL,
    -- HMAC-SHA3-256 blind index of the normalised file name, keyed per user.
    name_tag                  BYTEA                    NOT NULL,
    size_bytes                BIGINT                   NOT NULL,
    blob_key                  VARCHAR(64)              NOT NULL,
    signature                 BYTEA,
    signature_algorithm       VARCHAR(32),
    signer_key_fingerprint    VARCHAR(64),
    uploaded_at               TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at                TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at                TIMESTAMP WITH TIME ZONE NOT NULL,
    version                   BIGINT                   NOT NULL,
    CONSTRAINT pk_stored_file PRIMARY KEY (id),
    CONSTRAINT fk_stored_file_owner FOREIGN KEY (owner_id) REFERENCES user_account (id) ON DELETE CASCADE,
    CONSTRAINT uk_stored_file_owner_name UNIQUE (owner_id, name_tag),
    CONSTRAINT uk_stored_file_blob UNIQUE (blob_key),
    CONSTRAINT ck_stored_file_size CHECK (size_bytes >= 0)
);
CREATE INDEX ix_stored_file_owner ON stored_file (owner_id);
