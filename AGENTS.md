# Coding Rules
- Cross-project integration source of truth:
- Before changing any shared auth, API contract, routing ownership, or backend integration flow across `pos`, `api-sales`, `api-stocks`, `api-commercial`, and `api-auth`, read `/home/fedora/dev/POS_BACKEND_ALIGNMENT.md`.
- If local assumptions conflict with that document on cross-project architecture, follow `/home/fedora/dev/POS_BACKEND_ALIGNMENT.md` unless the user explicitly overrides it.

- Use **two-space indentation**, no tabs.
- Avoid adding dependencies when possible.
- Apply KISS practices.

# Response Preference
- Keep answers short and horizontal because the user cannot scroll easily.
- Avoid long vertical lists; prefer one compact paragraph or one-line flow.
- If an answer needs length, write it to `rpta.html` and tell the user.

# Commit Rules
- Keep route handlers small and grouped by resource.
- Use imperative commit prefixes: `feat:`, `fix:`, `refactor:`, `docs:`. May there be more than one in a single commit.
- Commit messages must include a prefix (feat/fix/refactor/docs) plus minimal bullet-like summaries of the main changes on subsequent lines. bullets must be plus signs "+ ".

# Security Checklist
- Never commit `.env` or credentials.
- Validate tokens in all routes except `/auth/login`.
- Verify expired or revoked tokens are blocked.
- Restrict DB roles to least privilege.

# Integration Notes
- Every Eqeqo API must check user access through `/check-permission`.
- Bridges or frontends may verify hash locally when possible.

# Testing Guidelines
- Tests require a seeded DB from `db/run_all.sql`.
- Use names like `login_behaves_as_expected` for consistency.

# Deployment Preference
- After finishing code changes for this service, deploy and restart `api-auth` without waiting for an extra request.
