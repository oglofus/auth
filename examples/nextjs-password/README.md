# Next.js Password Example

Files:

- `auth.ts`: in-memory adapters + `OglofusAuth` with `passwordPlugin`.
- `register-route.ts`: register endpoint.
- `login-route.ts`: login endpoint.
- `session-route.ts`: validate/sign-out endpoints.

Framework:

- Next.js route handlers

Notes:

- The example returns `sessionId` in JSON for clarity; in production you would usually set an HTTP-only cookie instead.
- Replace the in-memory user/session/password stores with database-backed adapters.
