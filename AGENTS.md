# AGENTS.md — Eqeqo Auth API

## 🔧 Tasks for agents
1. **Generate all success and fail tests in the currents api_test.rs file.**
   - Use the current structure, fixing server creation error and updating test cases on the list. dont change test technique.
3. **Add token renewal logic**
- keep it minimal.
5. **Require header `token:` in all protected routes.**
6. **On user delete**, remove related tokens.
7. **Add minimal logging**
   - Record token, endpoint, timestamp, IP.
8. **Add cleanup job**
   - Periodically remove expired tokens.


**Done criteria:**
- Token-based auth fully functional.
- Centralized cache in DB.
- Renewal atomic, short TTL.
- No token leaks via URL.
- Minimal overhead, max security.

## Rol
Central identity and authorization API for the Eqeqo ecosystem.
Manages users, services, roles, and permissions.
Issues and validates access tokens for all other APIs.

## Coding & Commit Rules
- Use **two-space indentation**, no tabs.
- Keep route handlers small and grouped by resource.
- Use `serde::Serialize` for DTOs.
- Use imperative commit prefixes: `feat:`, `fix:`, `refactor:`, `docs:`.
- Include SQL or curl samples in PRs that change endpoints.
- Updates on db structure must be done in original db code, no migrations yet. None should be need by now.
- Avoid adding dependencies.
- Keep processes minimal.

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
- Tests require a seeded `auth_api` DB from `db/run_all.sql`.
- Use names like `login_behaves_as_expected` for consistency.
