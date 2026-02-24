# SvelteKit Email OTP Example

Files:

- `auth.ts`: in-memory adapters + `emailOtpPlugin`.
- `request-otp.server.ts`: sends an OTP and returns `challengeId`.
- `verify-otp.server.ts`: login with OTP, or auto-register if account does not exist.

The delivery handler logs OTP codes to console for local development.
