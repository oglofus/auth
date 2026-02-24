# Examples

This folder contains practical integration examples for `@oglofus/auth`.

- `nextjs-password/`: basic email + password auth in Next.js route handlers.
- `sveltekit-email-otp/`: OTP request + verify flow in SvelteKit endpoints.
- `oauth2-google-arctic/`: Google OAuth2 using `arctic` + profile completion.
- `two-factor-totp-oslo/`: password login gated by TOTP 2FA using `@oslojs/otp`.

All examples use in-memory adapters for clarity. Replace them with your database adapters in production.
