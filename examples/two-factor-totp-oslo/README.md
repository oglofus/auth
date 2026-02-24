# Two-Factor TOTP (Oslo OTP) Example

Files:

- `auth.ts`: password + `twoFactorPlugin` setup with TOTP and recovery stores.
- `login-step1-route.ts`: first login step; returns `TWO_FACTOR_REQUIRED` when needed.
- `login-step2-route.ts`: verifies TOTP using `auth.verifySecondFactor`.
- `totp-enrollment-routes.ts`: starts and confirms TOTP enrollment.

The plugin uses `@oslojs/otp` internally for TOTP verification and key URI generation.
