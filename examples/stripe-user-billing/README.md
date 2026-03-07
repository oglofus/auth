# Stripe User Billing Example

Files:

- `auth.ts`: in-memory billing adapters + `stripePlugin` configured for user subscriptions.
- `checkout-route.ts`: creates a Checkout session for the current user.
- `billing-portal-route.ts`: creates a Billing Portal session for the current user.
- `subscription-route.ts`: reads the local subscription snapshot and entitlements for the current user.
- `webhook-route.ts`: validates a raw Stripe webhook request and updates local billing state.

Framework:

- Next.js route handlers

Notes:

- Replace the in-memory customer/subscription/event/trial stores with your database adapters.
- Expose `auth.method("stripe").handleWebhook(...)` from your framework's raw-body webhook route.
- Install `stripe` in the host app and provide a real secret key + webhook secret.
