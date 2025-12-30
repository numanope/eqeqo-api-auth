# Coding Rules
- Use **two-space indentation**, no tabs.
- Avoid adding dependencies when possible.
- Apply KISS practices.

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
