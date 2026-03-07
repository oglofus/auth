import assert from "node:assert/strict";
import test from "node:test";

import Stripe from "stripe";

import {
  OglofusAuth,
  stripePlugin,
  type StripeSubject,
  type StripeSubscriptionSnapshot,
  type UserBase,
} from "../src/index.js";
import { createSessionStore, createStripeBillingStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

type Feature = "analytics" | "priority_support";
type LimitKey = "projects" | "seats";

const WEBHOOK_SECRET = "whsec_test_secret";

const toUnix = (date: Date): number => Math.floor(date.getTime() / 1_000);

const createSubscriptionFixture = (input: {
  id: string;
  customerId: string;
  priceId?: string;
  itemId?: string;
  status?: Stripe.Subscription.Status;
  quantity?: number;
  metadata?: Record<string, string>;
  cancelAtPeriodEnd?: boolean;
  canceledAt?: number | null;
  items?: Array<{ id?: string; priceId: string; quantity?: number }>;
}): Stripe.Subscription =>
  ({
    id: input.id,
    object: "subscription",
    customer: input.customerId,
    status: input.status ?? "active",
    cancel_at_period_end: input.cancelAtPeriodEnd ?? false,
    canceled_at: input.canceledAt ?? null,
    current_period_start: toUnix(new Date("2026-01-01T00:00:00Z")),
    current_period_end: toUnix(new Date("2026-02-01T00:00:00Z")),
    trial_start: null,
    trial_end: null,
    metadata: input.metadata ?? {},
    items: {
      object: "list",
      data:
        input.items?.map((item, index) => ({
          id: item.id ?? `${input.itemId ?? `si_${input.id}`}_${index}`,
          object: "subscription_item",
          quantity: item.quantity ?? input.quantity ?? 1,
          price: {
            id: item.priceId,
            object: "price",
          },
        })) ??
        (input.priceId
          ? [
              {
                id: input.itemId ?? `si_${input.id}`,
                object: "subscription_item",
                quantity: input.quantity ?? 1,
                price: {
                  id: input.priceId,
                  object: "price",
                },
              },
            ]
          : []),
    },
  }) as unknown as Stripe.Subscription;

const createFakeStripeClient = () => {
  const realStripe = new Stripe("sk_test_123");
  let customerCounter = 0;
  let checkoutCounter = 0;
  const customers = new Map<string, { id: string; email?: string; metadata?: Record<string, string> }>();
  const subscriptions = new Map<string, Stripe.Subscription>();
  const checkoutCalls: Array<Record<string, unknown>> = [];
  const scheduleCalls: Array<Record<string, unknown>> = [];

  const stripe = {
    webhooks: realStripe.webhooks,
    customers: {
      create: async (params: { email?: string; metadata?: Record<string, string> }) => {
        const id = `cus_${++customerCounter}`;
        customers.set(id, {
          id,
          email: params.email,
          metadata: params.metadata,
        });
        return { id };
      },
    },
    checkout: {
      sessions: {
        create: async (params: Record<string, unknown>) => {
          checkoutCalls.push(params);
          return {
            id: `cs_${++checkoutCounter}`,
            url: `https://checkout.stripe.test/session/${checkoutCounter}`,
          };
        },
      },
    },
    billingPortal: {
      sessions: {
        create: async (_params: Record<string, unknown>) => ({
          url: "https://billing.stripe.test/session",
        }),
      },
    },
    subscriptions: {
      retrieve: async (id: string) => {
        const subscription = subscriptions.get(id);
        if (!subscription) {
          throw new Error(`missing subscription ${id}`);
        }
        return subscription;
      },
      update: async (id: string, params: Record<string, unknown>) => {
        const current = subscriptions.get(id);
        if (!current) {
          throw new Error(`missing subscription ${id}`);
        }

        const next = {
          ...current,
          cancel_at_period_end:
            typeof params.cancel_at_period_end === "boolean"
              ? params.cancel_at_period_end
              : current.cancel_at_period_end,
          metadata:
            params.metadata && typeof params.metadata === "object"
              ? (params.metadata as Record<string, string>)
              : current.metadata,
        } as Stripe.Subscription;

        if (Array.isArray(params.items) && params.items.length > 0) {
          const itemPatch = params.items[0] as { price?: string; quantity?: number };
          const currentItem = next.items.data[0];
          next.items = {
            ...next.items,
            data: [
              {
                ...currentItem,
                quantity: itemPatch.quantity ?? currentItem?.quantity ?? 1,
                price: {
                  ...currentItem?.price,
                  id: itemPatch.price ?? currentItem?.price?.id ?? "",
                },
              },
            ],
          };
        }

        subscriptions.set(id, next);
        return next;
      },
      cancel: async (id: string) => {
        const current = subscriptions.get(id);
        if (!current) {
          throw new Error(`missing subscription ${id}`);
        }
        const canceled = {
          ...current,
          status: "canceled",
          cancel_at_period_end: false,
          canceled_at: toUnix(new Date("2026-01-15T00:00:00Z")),
        } as Stripe.Subscription;
        subscriptions.set(id, canceled);
        return canceled;
      },
    },
    subscriptionSchedules: {
      create: async (params: Record<string, unknown>) => {
        scheduleCalls.push(params);
        return { id: `sub_sched_${scheduleCalls.length}` };
      },
    },
  } as unknown as Stripe;

  return {
    stripe,
    customers,
    subscriptions,
    checkoutCalls,
    scheduleCalls,
  };
};

const createSignedEvent = (stripe: Stripe, event: Stripe.Event): { payload: string; signature: string } => {
  const payload = JSON.stringify(event);
  const signature = stripe.webhooks.generateTestHeaderString({
    payload,
    secret: WEBHOOK_SECRET,
  });
  return { payload, signature };
};

const createAuth = (options?: {
  customerMode?: "user" | "organization" | "both";
  includeUser?: boolean;
  includeOrganizationPlan?: boolean;
}) => {
  const users = createUserStore<User>([
    ...(options?.includeUser === false
      ? []
      : [
          {
            id: "user_1",
            email: "nikos@example.com",
            emailVerified: true,
            given_name: "Nikos",
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ]),
  ]);
  const sessions = createSessionStore();
  const billing = createStripeBillingStore<Feature, LimitKey>();
  const stripeState = createFakeStripeClient();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      stripePlugin<User, Feature, LimitKey>({
        stripe: stripeState.stripe,
        webhookSecret: WEBHOOK_SECRET,
        customerMode: options?.customerMode ?? "both",
        plans: [
          {
            key: "starter",
            displayName: "Starter",
            scope: "user",
            prices: {
              monthly: { priceId: "price_starter_monthly" },
            },
            trial: {
              days: 14,
            },
            features: {
              analytics: true,
            },
            limits: {
              projects: 3,
            },
          },
          ...(options?.includeOrganizationPlan === false
            ? []
            : [
                {
                  key: "team",
                  displayName: "Team",
                  scope: "organization",
                  prices: {
                    monthly: { priceId: "price_team_monthly" },
                    annual: { priceId: "price_team_annual" },
                  },
                  seats: {
                    enabled: true,
                    minimum: 2,
                    limitKey: "seats",
                  },
                  features: {
                    analytics: true,
                    priority_support: true,
                  },
                  limits: {
                    projects: 20,
                  },
                },
              ]),
          {
            key: "pro",
            displayName: "Pro",
            scope: "user",
            prices: {
              annual: { priceId: "price_pro_annual" },
            },
            features: {
              analytics: true,
              priority_support: true,
            },
            limits: {
              projects: 100,
            },
          },
        ] as const,
        handlers: {
          customers: billing.customers,
          subscriptions: billing.subscriptions,
          events: billing.events,
          trials: billing.trials,
        },
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  return {
    auth,
    stripeState,
    billing,
  };
};

test("stripe checkout reuses customers and blocks repeat trial after cancellation", async () => {
  const { auth, stripeState } = createAuth();
  const api = auth.method("stripe");
  const subject: StripeSubject = { kind: "user", userId: "user_1" };

  const firstCheckout = await api.createCheckoutSession({
    subject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  assert.equal(firstCheckout.ok, true);
  assert.equal(stripeState.customers.size, 1);

  const secondCheckout = await api.createCheckoutSession({
    subject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  assert.equal(secondCheckout.ok, true);
  assert.equal(stripeState.customers.size, 1);

  const customerId = [...stripeState.customers.keys()][0]!;
  const subscription = createSubscriptionFixture({
    id: "sub_user_1",
    customerId,
    priceId: "price_starter_monthly",
    metadata: {
      oglofus_subject_kind: "user",
      oglofus_subject_id: "user_1",
      oglofus_plan_key: "starter",
      oglofus_billing_cycle: "monthly",
    },
  });
  stripeState.subscriptions.set(subscription.id, subscription);

  const createdEvent = createSignedEvent(stripeState.stripe, {
    id: "evt_sub_created",
    object: "event",
    type: "customer.subscription.created",
    data: { object: subscription },
  } as unknown as Stripe.Event);
  const processedCreated = await api.handleWebhook({
    rawBody: createdEvent.payload,
    stripeSignature: createdEvent.signature,
  });
  assert.equal(processedCreated.ok, true);

  const cancelResult = await api.cancelSubscription({ subject });
  assert.equal(cancelResult.ok, true);

  const retryCheckout = await api.createCheckoutSession({
    subject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  assert.equal(retryCheckout.ok, false);
  if (!retryCheckout.ok) {
    assert.equal(retryCheckout.error.code, "TRIAL_NOT_AVAILABLE");
  }
});

test("stripe billing portal requires a customer and webhook signatures are validated", async () => {
  const { auth, stripeState } = createAuth();
  const api = auth.method("stripe");
  const orgSubject: StripeSubject = { kind: "organization", organizationId: "org_1" };

  const missingCustomer = await api.createBillingPortalSession({
    subject: orgSubject,
    returnUrl: "https://app.example.com/billing",
  });
  assert.equal(missingCustomer.ok, false);
  if (!missingCustomer.ok) {
    assert.equal(missingCustomer.error.code, "CUSTOMER_NOT_FOUND");
  }

  const checkout = await api.createCheckoutSession({
    subject: orgSubject,
    planKey: "team",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
    seats: 4,
  });
  assert.equal(checkout.ok, true);

  const portal = await api.createBillingPortalSession({
    subject: orgSubject,
    returnUrl: "https://app.example.com/billing",
  });
  assert.equal(portal.ok, true);
  if (portal.ok) {
    assert.match(portal.data.url, /billing\.stripe\.test/);
  }

  const badWebhook = await api.handleWebhook({
    rawBody: JSON.stringify({ id: "evt_bad" }),
    stripeSignature: "invalid",
  });
  assert.equal(badWebhook.ok, false);
  if (!badWebhook.ok) {
    assert.equal(badWebhook.error.code, "STRIPE_WEBHOOK_INVALID");
  }
});

test("stripe webhooks sync snapshots, dedupe events, and remove entitlements for past_due subscriptions", async () => {
  const { auth, stripeState, billing } = createAuth();
  const api = auth.method("stripe");
  const subject: StripeSubject = { kind: "organization", organizationId: "org_1" };

  await api.createCheckoutSession({
    subject,
    planKey: "team",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
    seats: 5,
  });

  const customerId = [...stripeState.customers.keys()][0]!;
  const subscription = createSubscriptionFixture({
    id: "sub_org_1",
    customerId,
    priceId: "price_team_monthly",
    quantity: 5,
    metadata: {
      oglofus_subject_kind: "organization",
      oglofus_subject_id: "org_1",
      oglofus_plan_key: "team",
      oglofus_billing_cycle: "monthly",
    },
  });
  stripeState.subscriptions.set(subscription.id, subscription);

  const created = createSignedEvent(stripeState.stripe, {
    id: "evt_org_created",
    object: "event",
    type: "customer.subscription.created",
    data: { object: subscription },
  } as unknown as Stripe.Event);

  const first = await api.handleWebhook({
    rawBody: created.payload,
    stripeSignature: created.signature,
  });
  assert.equal(first.ok, true);

  const second = await api.handleWebhook({
    rawBody: created.payload,
    stripeSignature: created.signature,
  });
  assert.equal(second.ok, true);
  assert.equal(billing.processedEvents.size, 1);

  const entitlements = await api.getEntitlements({ subject });
  assert.equal(entitlements.ok, true);
  if (entitlements.ok) {
    assert.equal(entitlements.data.features.analytics, true);
    assert.equal(entitlements.data.features.priority_support, true);
    assert.equal(entitlements.data.limits.projects, 20);
    assert.equal(entitlements.data.limits.seats, 5);
  }

  stripeState.subscriptions.set(subscription.id, {
    ...subscription,
    status: "past_due",
  } as Stripe.Subscription);
  const paymentFailed = createSignedEvent(stripeState.stripe, {
    id: "evt_invoice_failed",
    object: "event",
    type: "invoice.payment_failed",
    data: {
      object: {
        id: "in_1",
        object: "invoice",
        subscription: subscription.id,
      },
    },
  } as unknown as Stripe.Event);

  const processedFailed = await api.handleWebhook({
    rawBody: paymentFailed.payload,
    stripeSignature: paymentFailed.signature,
  });
  assert.equal(processedFailed.ok, true);

  const noEntitlements = await api.getEntitlements({ subject });
  assert.equal(noEntitlements.ok, true);
  if (noEntitlements.ok) {
    assert.deepEqual(noEntitlements.data.features, {});
    assert.deepEqual(noEntitlements.data.limits, {});
    assert.equal(noEntitlements.data.status, "past_due");
  }
});

test("stripe lifecycle methods update snapshots and preserve current plan on scheduled changes", async () => {
  const { auth, stripeState, billing } = createAuth();
  const api = auth.method("stripe");
  const subject: StripeSubject = { kind: "user", userId: "user_1" };

  await api.createCheckoutSession({
    subject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  const customerId = [...stripeState.customers.keys()][0]!;
  stripeState.subscriptions.set(
    "sub_lifecycle",
    createSubscriptionFixture({
      id: "sub_lifecycle",
      customerId,
      priceId: "price_starter_monthly",
      metadata: {
        oglofus_subject_kind: "user",
        oglofus_subject_id: "user_1",
        oglofus_plan_key: "starter",
        oglofus_billing_cycle: "monthly",
      },
    }),
  );

  const created = createSignedEvent(stripeState.stripe, {
    id: "evt_lifecycle_created",
    object: "event",
    type: "customer.subscription.created",
    data: { object: stripeState.subscriptions.get("sub_lifecycle")! },
  } as unknown as Stripe.Event);
  await api.handleWebhook({
    rawBody: created.payload,
    stripeSignature: created.signature,
  });

  const changeImmediate = await api.changePlan({
    subject,
    planKey: "pro",
    billingCycle: "annual",
  });
  assert.equal(changeImmediate.ok, true);
  if (changeImmediate.ok) {
    assert.equal(changeImmediate.data.subscription.planKey, "pro");
    assert.equal(changeImmediate.data.subscription.billingCycle, "annual");
  }

  const scheduleChange = await api.changePlan({
    subject,
    planKey: "starter",
    billingCycle: "monthly",
    scheduleAtPeriodEnd: true,
  });
  assert.equal(scheduleChange.ok, true);
  if (scheduleChange.ok) {
    assert.equal(scheduleChange.data.subscription.planKey, "pro");
  }
  assert.equal(stripeState.scheduleCalls.length, 1);

  const cancelAtEnd = await api.cancelSubscription({
    subject,
    atPeriodEnd: true,
  });
  assert.equal(cancelAtEnd.ok, true);
  if (cancelAtEnd.ok) {
    assert.equal(cancelAtEnd.data.subscription.cancelAtPeriodEnd, true);
  }

  const resume = await api.resumeSubscription({ subject });
  assert.equal(resume.ok, true);
  if (resume.ok) {
    assert.equal(resume.data.subscription.cancelAtPeriodEnd, false);
  }

  const cancelNow = await api.cancelSubscription({ subject });
  assert.equal(cancelNow.ok, true);
  if (cancelNow.ok) {
    assert.equal(cancelNow.data.subscription.status, "canceled");
  }

  const snapshot = billing.subscriptionsByStripeId.get("sub_lifecycle") as
    | StripeSubscriptionSnapshot<Feature, LimitKey>
    | undefined;
  assert.equal(snapshot?.status, "canceled");
});

test("stripe validates subject scope, billing cycle, seats, missing users, and duplicate subscriptions", async () => {
  const disabledAuth = createAuth({ customerMode: "user", includeOrganizationPlan: false });
  const disabledApi = disabledAuth.auth.method("stripe");
  const disabledSubject: StripeSubject = { kind: "organization", organizationId: "org_1" };

  const disabled = await disabledApi.createCheckoutSession({
    subject: disabledSubject,
    planKey: "team",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
    seats: 2,
  });
  assert.equal(disabled.ok, false);
  if (!disabled.ok) {
    assert.equal(disabled.error.code, "INVALID_INPUT");
  }

  const { auth, stripeState } = createAuth();
  const api = auth.method("stripe");
  const userSubject: StripeSubject = { kind: "user", userId: "user_1" };
  const orgSubject: StripeSubject = { kind: "organization", organizationId: "org_1" };

  const invalidCycle = await api.createCheckoutSession({
    subject: userSubject,
    planKey: "starter",
    billingCycle: "annual",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  assert.equal(invalidCycle.ok, false);
  if (!invalidCycle.ok) {
    assert.equal(invalidCycle.error.code, "INVALID_INPUT");
  }

  const nonSeatPlan = await api.createCheckoutSession({
    subject: userSubject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
    seats: 2,
  });
  assert.equal(nonSeatPlan.ok, false);
  if (!nonSeatPlan.ok) {
    assert.equal(nonSeatPlan.error.code, "INVALID_INPUT");
  }

  const lowSeats = await api.createCheckoutSession({
    subject: orgSubject,
    planKey: "team",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
    seats: 1,
  });
  assert.equal(lowSeats.ok, false);
  if (!lowSeats.ok) {
    assert.equal(lowSeats.error.code, "INVALID_INPUT");
  }

  const highSeats = await api.createCheckoutSession({
    subject: orgSubject,
    planKey: "team",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
    seats: 1.5,
  });
  assert.equal(highSeats.ok, false);
  if (!highSeats.ok) {
    assert.equal(highSeats.error.code, "INVALID_INPUT");
  }

  const missingUserAuth = createAuth({ includeUser: false });
  const missingUser = await missingUserAuth.auth.method("stripe").createCheckoutSession({
    subject: userSubject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  assert.equal(missingUser.ok, false);
  if (!missingUser.ok) {
    assert.equal(missingUser.error.code, "USER_NOT_FOUND");
  }

  await api.createCheckoutSession({
    subject: userSubject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  const customerId = [...stripeState.customers.keys()][0]!;
  const subscription = createSubscriptionFixture({
    id: "sub_duplicate",
    customerId,
    priceId: "price_starter_monthly",
    metadata: {
      oglofus_subject_kind: "user",
      oglofus_subject_id: "user_1",
      oglofus_plan_key: "starter",
      oglofus_billing_cycle: "monthly",
    },
  });
  stripeState.subscriptions.set(subscription.id, subscription);
  const created = createSignedEvent(stripeState.stripe, {
    id: "evt_duplicate_created",
    object: "event",
    type: "customer.subscription.created",
    data: { object: subscription },
  } as unknown as Stripe.Event);
  await api.handleWebhook({
    rawBody: created.payload,
    stripeSignature: created.signature,
  });

  const duplicate = await api.createCheckoutSession({
    subject: userSubject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  assert.equal(duplicate.ok, false);
  if (!duplicate.ok) {
    assert.equal(duplicate.error.code, "SUBSCRIPTION_ALREADY_EXISTS");
  }
});

test("stripe lifecycle APIs reject invalid resume, ownership, and missing subscription item cases", async () => {
  const { auth, stripeState, billing } = createAuth();
  const api = auth.method("stripe");
  const userSubject: StripeSubject = { kind: "user", userId: "user_1" };
  const otherSubject: StripeSubject = { kind: "organization", organizationId: "org_2" };

  await api.createCheckoutSession({
    subject: userSubject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  const customerId = [...stripeState.customers.keys()][0]!;
  const subscription = createSubscriptionFixture({
    id: "sub_resume_conflicts",
    customerId,
    priceId: "price_starter_monthly",
    metadata: {
      oglofus_subject_kind: "user",
      oglofus_subject_id: "user_1",
      oglofus_plan_key: "starter",
      oglofus_billing_cycle: "monthly",
    },
  });
  stripeState.subscriptions.set(subscription.id, subscription);
  const created = createSignedEvent(stripeState.stripe, {
    id: "evt_resume_created",
    object: "event",
    type: "customer.subscription.created",
    data: { object: subscription },
  } as unknown as Stripe.Event);
  await api.handleWebhook({
    rawBody: created.payload,
    stripeSignature: created.signature,
  });

  const notScheduled = await api.resumeSubscription({ subject: userSubject });
  assert.equal(notScheduled.ok, false);
  if (!notScheduled.ok) {
    assert.equal(notScheduled.error.code, "CONFLICT");
  }

  const wrongOwner = await api.cancelSubscription({
    subject: otherSubject,
    subscriptionId: subscription.id,
  });
  assert.equal(wrongOwner.ok, false);
  if (!wrongOwner.ok) {
    assert.equal(wrongOwner.error.code, "SUBSCRIPTION_NOT_FOUND");
  }

  const wrongOwnerChange = await api.changePlan({
    subject: otherSubject,
    subscriptionId: subscription.id,
    planKey: "team",
    billingCycle: "monthly",
    seats: 2,
  });
  assert.equal(wrongOwnerChange.ok, false);
  if (!wrongOwnerChange.ok) {
    assert.equal(wrongOwnerChange.error.code, "SUBSCRIPTION_NOT_FOUND");
  }

  const canceled = await api.cancelSubscription({ subject: userSubject });
  assert.equal(canceled.ok, true);
  if (!canceled.ok) {
    return;
  }

  const resumeCanceled = await api.resumeSubscription({
    subject: userSubject,
    subscriptionId: subscription.id,
  });
  assert.equal(resumeCanceled.ok, false);
  if (!resumeCanceled.ok) {
    assert.equal(resumeCanceled.error.code, "CONFLICT");
  }

  stripeState.subscriptions.set(
    "sub_missing_item",
    createSubscriptionFixture({
      id: "sub_missing_item",
      customerId,
      items: [],
      metadata: {
        oglofus_subject_kind: "user",
        oglofus_subject_id: "user_1",
        oglofus_plan_key: "starter",
        oglofus_billing_cycle: "monthly",
      },
    }),
  );
  const missingItemSnapshot = {
    ...(canceled.data.subscription as StripeSubscriptionSnapshot<Feature, LimitKey>),
    stripeSubscriptionId: "sub_missing_item",
    status: "active" as const,
    cancelAtPeriodEnd: false,
  };
  await billing.subscriptions.upsert(missingItemSnapshot);

  const missingItem = await api.changePlan({
    subject: userSubject,
    subscriptionId: "sub_missing_item",
    planKey: "pro",
    billingCycle: "annual",
  });
  assert.equal(missingItem.ok, false);
  if (!missingItem.ok) {
    assert.equal(missingItem.error.code, "INTERNAL_ERROR");
  }
});

test("stripe webhooks recover subjects from customer mappings and handle restoration/error paths", async () => {
  const { auth, stripeState, billing } = createAuth();
  const api = auth.method("stripe");
  const subject: StripeSubject = { kind: "user", userId: "user_1" };

  await api.createCheckoutSession({
    subject,
    planKey: "starter",
    billingCycle: "monthly",
    successUrl: "https://app.example.com/success",
    cancelUrl: "https://app.example.com/cancel",
  });
  const customerId = [...stripeState.customers.keys()][0]!;
  const subscription = createSubscriptionFixture({
    id: "sub_recovery",
    customerId,
    priceId: "price_starter_monthly",
    metadata: {
      oglofus_subject_kind: "user",
      oglofus_subject_id: "user_1",
      oglofus_plan_key: "starter",
      oglofus_billing_cycle: "monthly",
    },
  });
  stripeState.subscriptions.set(subscription.id, subscription);

  const completed = createSignedEvent(stripeState.stripe, {
    id: "evt_checkout_completed",
    object: "event",
    type: "checkout.session.completed",
    data: {
      object: {
        id: "cs_1",
        object: "checkout.session",
        customer: customerId,
        subscription: subscription.id,
        metadata: {},
      },
    },
  } as unknown as Stripe.Event);
  const processed = await api.handleWebhook({
    rawBody: completed.payload,
    stripeSignature: completed.signature,
  });
  assert.equal(processed.ok, true);
  assert.equal(billing.subscriptionsByStripeId.get(subscription.id)?.subject.kind, "user");

  stripeState.subscriptions.set(subscription.id, {
    ...subscription,
    status: "past_due",
  } as Stripe.Subscription);
  const failed = createSignedEvent(stripeState.stripe, {
    id: "evt_restore_failed",
    object: "event",
    type: "invoice.payment_failed",
    data: { object: { id: "in_fail", object: "invoice", subscription: subscription.id } },
  } as unknown as Stripe.Event);
  await api.handleWebhook({
    rawBody: failed.payload,
    stripeSignature: failed.signature,
  });

  stripeState.subscriptions.set(subscription.id, {
    ...subscription,
    status: "active",
  } as Stripe.Subscription);
  const paid = createSignedEvent(stripeState.stripe, {
    id: "evt_restore_paid",
    object: "event",
    type: "invoice.paid",
    data: { object: { id: "in_paid", object: "invoice", subscription: subscription.id } },
  } as unknown as Stripe.Event);
  const restored = await api.handleWebhook({
    rawBody: paid.payload,
    stripeSignature: paid.signature,
  });
  assert.equal(restored.ok, true);

  const entitlements = await api.getEntitlements({ subject });
  assert.equal(entitlements.ok, true);
  if (entitlements.ok) {
    assert.equal(entitlements.data.features.analytics, true);
    assert.equal(entitlements.data.limits.projects, 3);
    assert.equal(entitlements.data.status, "active");
  }

  const unknownCustomer = createSignedEvent(stripeState.stripe, {
    id: "evt_unknown_customer",
    object: "event",
    type: "customer.subscription.created",
    data: {
      object: createSubscriptionFixture({
        id: "sub_unknown_customer",
        customerId: "cus_missing",
        priceId: "price_starter_monthly",
        metadata: {},
      }),
    },
  } as unknown as Stripe.Event);
  await assert.rejects(
    api.handleWebhook({
      rawBody: unknownCustomer.payload,
      stripeSignature: unknownCustomer.signature,
    }),
    (error: { code?: string }) => error.code === "CUSTOMER_NOT_FOUND",
  );

  const unknownPriceSubscription = createSubscriptionFixture({
    id: "sub_unknown_price",
    customerId,
    priceId: "price_unknown",
    metadata: {},
  });
  const unknownPrice = createSignedEvent(stripeState.stripe, {
    id: "evt_unknown_price",
    object: "event",
    type: "customer.subscription.created",
    data: { object: unknownPriceSubscription },
  } as unknown as Stripe.Event);
  await assert.rejects(
    api.handleWebhook({
      rawBody: unknownPrice.payload,
      stripeSignature: unknownPrice.signature,
    }),
    (error: { code?: string }) => error.code === "PLUGIN_MISCONFIGURED",
  );
});
