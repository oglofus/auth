# @oglofus/auth [![NPM Version](https://img.shields.io/npm/v/%40oglofus%2Fauth)](https://www.npmjs.com/package/@oglofus/auth) [![Publish Package to NPM](https://github.com/oglofus/auth/actions/workflows/release-package.yml/badge.svg)](https://github.com/oglofus/auth/actions/workflows/release-package.yml)

Type-safe, plugin-first authentication core for TypeScript applications.

## Features

- Plugin architecture for auth methods and domain capabilities.
- Strongly typed register/authenticate payloads inferred from enabled plugins.
- Path-based issue model (`{ message, path }`) for field-level error mapping.
- Built-in methods: password, email OTP, magic link, OAuth2, passkey.
- Built-in domain plugins: two-factor auth (TOTP/recovery code), organizations/RBAC.
- Framework-agnostic core for TypeScript apps running in Node-compatible server environments.

## Install

```bash
npm install @oglofus/auth
```

```bash
pnpm add @oglofus/auth
```

```bash
bun add @oglofus/auth
```

Optional for app-level integrations:

- `arctic` for OAuth providers in your app code.
- `@oslojs/otp` if you need direct OTP utilities in your app (the library already uses it internally for TOTP).

## Quick Start (Password)

```ts
import {
  OglofusAuth,
  passwordPlugin,
  type PasswordCredentialAdapter,
  type SessionAdapter,
  type UserAdapter,
  type UserBase,
} from "@oglofus/auth";

interface AppUser extends UserBase {
  given_name: string;
  family_name: string;
}

const users: UserAdapter<AppUser> = /* your adapter */;
const sessions: SessionAdapter = /* your adapter */;
const credentials: PasswordCredentialAdapter = /* your adapter */;

const auth = new OglofusAuth({
  adapters: { users, sessions },
  plugins: [
    passwordPlugin<AppUser, "given_name" | "family_name">({
      requiredProfileFields: ["given_name", "family_name"] as const,
      credentials,
    }),
  ] as const,
  validateConfigOnStart: true,
});

const registered = await auth.register({
  method: "password",
  email: "nikos@example.com",
  password: "super-secret",
  given_name: "Nikos",
  family_name: "Gram",
});

const loggedIn = await auth.authenticate({
  method: "password",
  email: "nikos@example.com",
  password: "super-secret",
});
```

## Core API

`OglofusAuth` exposes:

- `discover(input, request?)`
- `register(input, request?)`
- `authenticate(input, request?)`
- `method(pluginMethod)` for plugin-specific APIs
- `verifySecondFactor(input, request?)`
- `completeProfile(input, request?)`
- `validateSession(sessionId, request?)`
- `signOut(sessionId, request?)`

Organization session switching is exposed by the organizations plugin API:

```ts
const orgApi = auth.method("organizations");
await orgApi.setActiveOrganization({
  sessionId: "session_123",
  organizationId: "org_123",
});
await orgApi.setActiveOrganization({ sessionId: "session_123" }); // clear
```

## Result and Error Shape

All operations return structured results.

```ts
if (!result.ok) {
  console.log(result.error.code); // e.g. "INVALID_INPUT"
  console.log(result.error.status); // HTTP-friendly status code
  console.log(result.issues); // path-based issues
}
```

Issue format:

```ts
type Issue = {
  message: string;
  path?: ReadonlyArray<PropertyKey | { key: PropertyKey } | { index: number }>;
};
```

You can build issues with helpers:

```ts
import { createIssue, createIssueFactory } from "@oglofus/auth";

const issue = createIssueFactory<{ email: string; profile: unknown }>([
  "email",
  "profile",
] as const);
issue.email("Email is required");
issue.$path(
  ["profile", { key: "addresses" }, { index: 0 }, "city"],
  "City is required",
);
createIssue("Generic failure");
```

## Built-in Plugins

### Password

- Method: `"password"`
- Register + authenticate supported.
- Config: `requiredProfileFields`, `credentials` adapter.

### Email OTP

- Method: `"email_otp"`
- Two-step flow with plugin API:
  1. `auth.method("email_otp").request({ email })`
  2. `auth.authenticate(...)` or `auth.register(...)` with `challengeId` + `code`

### Magic Link

- Method: `"magic_link"`
- Two-step flow with plugin API:
  1. `auth.method("magic_link").request({ email })`
  2. `auth.authenticate(...)` or `auth.register(...)` with `token`

### OAuth2 (Arctic)

- Method: `"oauth2"`
- Uses provider exchange callbacks. Arctic clients can be wrapped with `arcticAuthorizationCodeExchange(...)`.
- Supports profile completion when required fields are missing.

```ts
import { Google } from "arctic";
import { arcticAuthorizationCodeExchange, oauth2Plugin } from "@oglofus/auth";

const google = new Google(process.env.GOOGLE_CLIENT_ID!, process.env.GOOGLE_CLIENT_SECRET!, process.env.GOOGLE_REDIRECT_URI!);

oauth2Plugin<AppUser, "google", "given_name" | "family_name">({
  providers: {
    google: {
      exchangeAuthorizationCode: arcticAuthorizationCodeExchange(google),
      resolveProfile: async ({ tokens }) => {
        const res = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
          headers: { Authorization: `Bearer ${tokens.accessToken()}` },
        });
        const p = await res.json() as {
          sub: string;
          email?: string;
          email_verified?: boolean;
          given_name?: string;
          family_name?: string;
        };
        return {
          providerUserId: p.sub,
          email: p.email,
          emailVerified: p.email_verified,
          profile: {
            given_name: p.given_name ?? "",
            family_name: p.family_name ?? "",
          },
        };
      },
      // pkceRequired defaults to true
    },
  },
  accounts: /* OAuth2AccountAdapter<"google"> */,
  requiredProfileFields: ["given_name", "family_name"] as const,
});

const result = await auth.authenticate({
  method: "oauth2",
  provider: "google",
  authorizationCode: "code-from-callback",
  redirectUri: process.env.GOOGLE_REDIRECT_URI!,
  codeVerifier: "pkce-code-verifier",
  idempotencyKey: "oauth-state",
});
```

### Passkey

- Method: `"passkey"`
- Register + authenticate supported.
- The package consumes already-verified passkey results; it does not perform raw WebAuthn attestation/assertion verification.
- Verify WebAuthn with `@simplewebauthn/server` or equivalent first, then pass the verified result into `auth.register(...)` / `auth.authenticate(...)`.
- Config: `requiredProfileFields`, `passkeys` adapter.

### Two-Factor (Domain Plugin)

- Method: `"two_factor"`
- Adds post-primary verification (`TWO_FACTOR_REQUIRED`).
- This release supports `totp` and `recovery_code`.
- Uses `@oslojs/otp` internally for TOTP verification and enrollment URI generation.
- Plugin API:
  - `beginTotpEnrollment(userId)`
  - `confirmTotpEnrollment({ enrollmentId, code })`
  - `regenerateRecoveryCodes(userId)`

### Organizations (Domain Plugin)

- Method: `"organizations"`
- Multi-tenant orgs, memberships, role inheritance, feature/limit entitlements, invites.
- Validates role topology on startup (default role, owner role presence, inheritance cycles).

## Account Discovery

Use `discover(...)` to support login/register routing logic before full auth:

- `private` mode: generic non-enumerating response.
- `explicit` mode: returns account-aware actions (`continue_login`, `redirect_register`, `redirect_login`).

`explicit` mode requires an `identity` adapter.

## Examples

See ready-to-copy integrations:

- [`examples/nextjs-password`](./examples/nextjs-password)
- [`examples/sveltekit-email-otp`](./examples/sveltekit-email-otp)
- [`examples/oauth2-google-arctic`](./examples/oauth2-google-arctic)
- [`examples/two-factor-totp-oslo`](./examples/two-factor-totp-oslo)

## Scripts

```bash
pnpm run typecheck
pnpm run test
pnpm run build
```

## Development

- Build: `pnpm run build` (outputs to `dist/`)
- TypeScript config: `tsconfig.json`

## License

ISC License. See the LICENSE file for details.

## Links

- Repository: https://github.com/oglofus/auth
- NPM: https://www.npmjs.com/package/@oglofus/auth
