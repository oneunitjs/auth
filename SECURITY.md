# Security Policy

## Supported Versions

Security fixes are provided for supported release lines of `@oneunit/auth`.

| Version | Supported |
| ------- | --------- |
| 2.1.x (current beta) | :white_check_mark: |
| 2.0.x | :white_check_mark: |
| < 2.0 | :x: |

Pre-release versions are supported on a best-effort basis until the next stable release.

## Reporting a Vulnerability

Please do **not** report security vulnerabilities through public GitHub issues, pull requests, or discussions.

Report vulnerabilities privately using GitHub Security Advisories:

- https://github.com/oneunitjs/auth/security/advisories/new

Please include:

- The affected `@oneunit/auth` version.
- A minimal reproduction or proof of concept.
- The expected and actual behavior.
- Any relevant configuration, including OAuth provider, storage adapter, and framework adapter details.
- An assessment of impact, if known.

## Response and Disclosure

- Initial acknowledgement is expected within 72 hours of receiving a report.
- Status updates are provided at least every 7 days while the report is being investigated.
- Confirmed vulnerabilities are fixed before public disclosure whenever practical.
- Credit is given to reporters unless anonymity is requested.
- Coordinated disclosure dates are agreed with the reporter for high-impact issues.

## Scope

In scope:

- JWT issuance, signing, verification, and claim validation.
- Refresh-token rotation, replay protection, and session versioning.
- OAuth/OIDC authorization-code flow, PKCE, state handling, and redirect URI validation.
- RBAC role inheritance, permission matching, and cache behavior.
- Password hashing integration and secret handling.
- Storage, event, and adapter contract behavior exposed by `@oneunit/auth`.
- HTTP transport security-relevant behavior, including timeouts, limits, and retry behavior.

Out of scope:

- Application-level concerns such as rate limiting, account lifecycle management, MFA, and email verification.
- Weak or leaked application secrets configured by consumers.
- Misuse of library APIs or failure to enforce authorization in application code.
- Vulnerabilities in third-party dependencies; report those to their maintainers.
- Custom storage, event, or logging implementations supplied by the application.

## Security Practices

- Never commit secrets, private keys, or production credentials.
- Use strong signing secrets and rotate them when compromise is suspected.
- Configure OAuth redirect URI allowlists explicitly.
- Prefer shared, durable storage for refresh tokens and sessions in production.
- Keep `@oneunit/auth` and Node.js updated to supported versions.
