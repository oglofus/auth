# Stripe Organization Billing Example

Files:

- `auth.ts`: `organizationsPlugin` + `stripePlugin` composed together for org billing.
- `checkout-route.ts`: creates a Checkout session for an organization subscription.
- `billing-portal-route.ts`: creates a Billing Portal session for the organization's customer.
- `entitlements-route.ts`: reads merged organization entitlements after Stripe plan composition.
- `webhook-route.ts`: validates a raw Stripe webhook request and updates local billing state.

Framework:

- Next.js route handlers

Notes:

- Stripe plan entitlements are merged into organization entitlement reads at runtime.
- Manual organization feature/limit overrides still win over plan-derived values.
- Seat quantities can drive an organization limit key when the Stripe plan sets `seats.limitKey`.
