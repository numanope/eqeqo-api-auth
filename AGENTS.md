# AGENTS.md

## Coding & Commit Rules
- Use **two-space indentation**, no tabs.
- Keep route handlers small and grouped by resource.
- Use imperative commit prefixes: `feat:`, `fix:`, `refactor:`, `docs:`. May there be more than one in a single commit.
- Commit messages must include a prefix (feat/fix/refactor/docs) plus minimal bullet-like summaries of the main changes on subsequent lines. bullets must be plus signs "+ ".
- Avoid adding dependencies when possible.
- Apply KISS practices.

## Security Checklist
- Never commit `.env` or credentials.
- Validate tokens in all routes except `/auth/login`.
- Verify expired or revoked tokens are blocked.
- Restrict DB roles to least privilege.

## Integration Notes
- Every Eqeqo API must check user access through `/check-permission`.
- Bridges or frontends may verify hash locally when possible.
- `Auth-API` logs all login and role assignment actions.

## Testing Guidelines
- Integration tests in `tests/integration.rs`.
- Tests require a seeded `api_auth` DB from `db/run_all.sql`.
- Use names like `login_behaves_as_expected` for consistency.
