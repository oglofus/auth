# OAuth2 Google (Arctic) Example

Files:

- `auth.ts`: `oauth2Plugin` configured with Arctic `Google` client.
- `start-route.ts`: starts OAuth flow and stores state + PKCE verifier in cookies.
- `callback-route.ts`: validates callback and calls `auth.authenticate`.

Required environment variables:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`

If Google does not return all required profile fields, the callback returns `PROFILE_COMPLETION_REQUIRED` with `pendingProfileId` and `missingFields`.
