# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] - unreleased

A ground-up rebuild of the 2020 coursework as a quantum-ready personal cloud drive.

### Added

- Hybrid post-quantum envelope encryption for every note, credential and file: X25519 +
  ML-KEM-768 (FIPS 203), an HKDF-SHA-512 combiner in the style of X-Wing, a per-item AES-256-GCM
  data key, and associated data that binds each ciphertext to its item, owner, kind and suite.
- Streaming file encryption (the STREAM construction over AES-256-GCM, 64 KiB segments), so
  uploads and downloads never buffer whole files in memory.
- ML-DSA-65 (FIPS 204) signatures over a canonical JSON manifest for every file, a
  **Verified** badge, and a signed manifest export. Downloads are verified before any byte is
  sent.
- Per-user key pairs wrapped with Argon2id (RFC 9106) and held unlocked only in session memory,
  wiped on sign-out. A one-time recovery key with checksum and rotation on use.
- Crypto agility: suite ids and versions on every row, a suite registry, automatic migration on
  login, and a Security page with per-item re-key and migrate-all actions.
- Optional `pqtls` profile: HTTPS through Bouncy Castle JSSE with TLS 1.3 and the
  X25519MLKEM768 hybrid key exchange.
- Optional `postgres` profile. Flyway schema with constraints for unique usernames, unique file
  names per user (through a keyed blind index) and well-formed credentials.
- Login lockout, per-client rate limiting, strict security headers (CSP, frame denial,
  `nosniff`, `no-referrer`, COOP, Permissions-Policy, HSTS over HTTPS), session fixation
  protection, and `SameSite=Strict` cookies.
- JUnit 5 test suite: crypto unit tests (round trip, tampering, wrong keys, truncation,
  reordering, agility and migration), JPA slice tests, service and MockMvc security tests,
  Selenium 4 end-to-end tests in headless Chrome, and a PQ-TLS handshake test.
- Multi-stage non-root Docker image, GitHub Actions CI with CodeQL, and Dependabot.
- `docs/CRYPTO.md` with the threat model, key hierarchy, formats, and an explicit list of what
  is not protected.

### Changed

- Spring Boot 2.2.4 to 3.5.16, Java 11 to 21, `javax.*` to `jakarta.*`, and Spring Security 6
  with the lambda DSL.
- MyBatis with hand-written SQL replaced by Spring Data JPA derived queries. The schema moved
  from `schema.sql` to Flyway.
- Password hashing from salted PBKDF2-SHA1 (5000 iterations) to Argon2id behind
  `DelegatingPasswordEncoder`. Existing hashes are upgraded at the next login.
- Credentials from AES/ECB with the key stored beside the ciphertext to the hybrid envelope.
  Legacy rows are decrypted once and re-sealed at login.
- Files moved from database BLOBs to an encrypted blob store with atomic, transactional
  publishing.
- Bootstrap 4 copied into the repository replaced by Bootstrap 5 and Bootstrap Icons from
  WebJars. Redesigned pages with no inline scripts or styles.
- Package renamed to `io.github.xlsarath.superduperdrive`. The application moved from
  `starter/cloudstorage` to the repository root.
- Selenium 3 and WebDriverManager replaced by Selenium 4 with Selenium Manager. Test data uses
  fictional names only.

### Fixed

- Delete actions were `GET` links and so were open to CSRF. They are now CSRF-protected `POST`s.
- Saving a credential always reported success because of a stray `;` after an `if`.
- Downloads were sent without `Content-Type` or `Content-Disposition` and could render
  uploaded HTML in the application's origin. They are now `application/octet-stream`
  attachments with a sandboxing CSP.
- `SECLET` typo in a notes query. Unscoped `getAllNotes`/`getAllFiles` queries that could
  return every user's data were removed; every lookup is now scoped to its owner.
- Usernames were not unique at the database level (a check-then-insert race), and the check was
  case-sensitive.
- Password hashes were compared with `String.equals` (not constant time), and unknown users
  skipped hashing, which made usernames discoverable through timing.
- Usernames and ids were printed to standard output with `System.out.println`.
- No input validation and no handling of oversized uploads. A failed download raised an
  unhandled `RuntimeException`.

### Removed

- MyBatis, H2 `schema.sql`, vendored jQuery, Popper and Bootstrap, `commons-io`,
  WebDriverManager, and the 2020 screenshots.

## [1.0.0] - 2020-07-10

- Udacity Java Web Developer Nanodegree project: file, note and credential storage with Spring
  Boot 2.2, MyBatis, H2, Thymeleaf and Selenium tests.

[2.0.0]: https://github.com/xlsarath/superduperdrive/compare/706803d...pqc-modernization
[1.0.0]: https://github.com/xlsarath/superduperdrive/tree/706803d
