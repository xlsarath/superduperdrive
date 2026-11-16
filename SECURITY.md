# Security policy

SuperDuperDrive is a showcase of post-quantum cryptography in a Spring Boot application. It has
not been independently audited. Read [docs/CRYPTO.md](docs/CRYPTO.md), and especially
[What is NOT protected](docs/CRYPTO.md#what-is-not-protected), before trusting it with real data.

## Supported versions

| Version | Supported |
|---|---|
| 2.x (`master`) | Yes |
| 1.x (2020 coursework) | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/xlsarath/superduperdrive/security/advisories/new)
rather than in a public issue. Include:

- what an attacker can do, and under which assumptions (database access, network position, a
  signed-in session, …);
- steps or a test that reproduce it;
- the commit you tested.

You can expect an acknowledgement within a week. Fixes are released on `master` and listed in
the [changelog](CHANGELOG.md). Credit is given in the advisory unless you prefer otherwise.

## Scope

In scope: the cryptographic design and its implementation, authentication and session handling,
access control between accounts, and injection, XSS, CSRF and file-handling issues.

Out of scope: findings that require control of the running server process (documented as not
protected), missing hardening of a deployment you configured yourself, and denial of service
through resource exhaustion on a single-node development setup.
