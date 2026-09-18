# Security review

## Scope

The review covered the public store, admin session flow, product and inventory APIs,
checkout, order storage, image handling, and static file serving.

## Findings and remediation

| Severity | Finding | Remediation |
|---|---|---|
| HIGH | The server could expose the backend directory and SQLite database through static serving. | Static serving was removed; only the frontend entry point is returned for browser routes. |
| HIGH | A known fallback admin password could be used when deployment configuration was missing. | `ADMIN_PASSWORD` is now mandatory at startup, and admin cookies support `Secure` by default. |

## Verification

- Unauthenticated admin requests return `401`.
- Backend source requests return the frontend shell, not server source.
- Product creation, checkout, stock decrement, order persistence, WhatsApp URL generation,
  and out-of-stock rejection were smoke-tested.
- SQLite integrity check returned `ok`.
