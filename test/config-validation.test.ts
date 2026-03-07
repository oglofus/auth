import assert from "node:assert/strict";
import test from "node:test";

import Stripe from "stripe";
import {
  OglofusAuth,
  organizationsPlugin,
  passwordPlugin,
  stripePlugin,
  type AuthMethodPlugin,
  type UserBase,
} from "../src/index.js";
import { createSessionStore, createStripeBillingStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {}

const createStripeStub = (): Stripe =>
  ({
    webhooks: new Stripe("sk_test_123").webhooks,
    customers: { create: async () => ({ id: "cus_1" }) },
    checkout: { sessions: { create: async () => ({ id: "cs_1", url: "https://checkout" }) } },
    billingPortal: { sessions: { create: async () => ({ url: "https://billing" }) } },
    subscriptions: {
      retrieve: async () => {
        throw new Error("no");
      },
      update: async () => {
        throw new Error("no");
      },
      cancel: async () => {
        throw new Error("no");
      },
    },
    subscriptionSchedules: {
      create: async () => ({ id: "sub_sched_1" }),
    },
  }) as unknown as Stripe;

const createBase = () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();

  return {
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
  };
};

test("duplicate plugin method names are rejected", () => {
  const base = createBase();

  const plugin = {
    kind: "auth_method",
    method: "duplicate",
    version: "1",
    supports: { register: false },
    authenticate: async () => {
      throw new Error("nope");
    },
  } as AuthMethodPlugin<"duplicate", { method: "duplicate" }, { method: "duplicate" }, User>;

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [plugin, plugin] as const,
      validateConfigOnStart: true,
    });
  });
});

test("auth method plugins with invalid register contract are rejected", () => {
  const base = createBase();

  const badPlugin = {
    kind: "auth_method",
    method: "bad",
    version: "1",
    supports: { register: true },
    authenticate: async () => {
      throw new Error("nope");
    },
  } as AuthMethodPlugin<"bad", { method: "bad" }, { method: "bad" }, User>;

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [badPlugin] as const,
      validateConfigOnStart: true,
    });
  });
});

test("organizations roles are validated on startup", () => {
  const base = createBase();

  const credentials = {
    getPasswordHash: async () => null,
    setPasswordHash: async () => {},
  };

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        passwordPlugin<User, never>({
          requiredProfileFields: [] as const,
          credentials,
        }),
        organizationsPlugin<
          User,
          { id: string; slug: string; name: string; billing_email: string; createdAt: Date; updatedAt: Date },
          "owner" | "member",
          {
            id: string;
            organizationId: string;
            userId: string;
            role: "owner" | "member";
            status: "active" | "invited" | "suspended";
            createdAt: Date;
            updatedAt: Date;
          },
          "members.manage",
          "sso",
          "seats",
          "billing_email"
        >({
          inviteBaseUrl: "https://example.com/invite",
          organizationRequiredFields: ["billing_email"] as const,
          handlers: {
            organizations: {
              create: async (input) => ({
                ...input,
                id: crypto.randomUUID(),
                createdAt: new Date(),
                updatedAt: new Date(),
              }),
              findById: async () => null,
              findBySlug: async () => null,
              update: async () => {
                throw new Error("no");
              },
            },
            organizationSessions: {
              setActiveOrganization: async () => null,
            },
            memberships: {
              create: async (input) => ({
                ...input,
                id: crypto.randomUUID(),
                createdAt: new Date(),
                updatedAt: new Date(),
              }),
              findById: async () => null,
              findByUserAndOrganization: async () => null,
              listByUser: async () => [],
              listByOrganization: async () => [],
              setRole: async () => {
                throw new Error("no");
              },
              setStatus: async () => {
                throw new Error("no");
              },
              delete: async () => {},
            },
            invites: {
              create: async () => {},
              findActiveByTokenHash: async () => null,
              consume: async () => false,
              revoke: async () => {},
            },
            inviteDelivery: {
              send: async () => ({ accepted: true }),
            },
            entitlements: {
              getFeatureOverrides: async () => ({}),
              getLimitOverrides: async () => ({}),
              setFeatureOverride: async () => {},
              setLimitOverride: async () => {},
            },
            roles: {
              owner: {
                permissions: ["members.manage"],
                system: { owner: true },
              },
              member: {
                permissions: [],
                // invalid: no system.default role at all
              },
            },
            defaultRole: "member",
          },
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});

test("duplicate stripe plugins are rejected", () => {
  const base = createBase();
  const billing = createStripeBillingStore<"analytics", "projects">();

  const plugin = stripePlugin<User, "analytics", "projects">({
    stripe: createStripeStub(),
    webhookSecret: "whsec_test",
    handlers: {
      customers: billing.customers,
      subscriptions: billing.subscriptions,
      events: billing.events,
      trials: billing.trials,
    },
    plans: [
      {
        key: "starter",
        displayName: "Starter",
        scope: "user",
        prices: {
          monthly: { priceId: "price_1" },
        },
      },
    ] as const,
  });

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [plugin, plugin] as const,
      validateConfigOnStart: true,
    });
  });
});

test("invalid stripe plan definitions are rejected on startup", () => {
  const base = createBase();
  const billing = createStripeBillingStore<"analytics", "projects">();

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        stripePlugin<User, "analytics", "projects">({
          stripe: createStripeStub(),
          webhookSecret: "whsec_test",
          handlers: {
            customers: billing.customers,
            subscriptions: billing.subscriptions,
            events: billing.events,
          },
          plans: [
            {
              key: "team",
              displayName: "Team",
              scope: "user",
              prices: {
                monthly: { priceId: "price_team" },
              },
              seats: {
                enabled: true,
              },
            },
          ] as const,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});

test("stripe plan requires at least one price", () => {
  const base = createBase();
  const billing = createStripeBillingStore<"analytics", "projects">();

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        stripePlugin<User, "analytics", "projects">({
          stripe: createStripeStub(),
          webhookSecret: "whsec_test",
          handlers: {
            customers: billing.customers,
            subscriptions: billing.subscriptions,
            events: billing.events,
          },
          plans: [
            {
              key: "empty",
              displayName: "Empty",
              scope: "user",
              prices: {},
            },
          ] as const,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});

test("duplicate stripe plan keys are rejected on startup", () => {
  const base = createBase();
  const billing = createStripeBillingStore<"analytics", "projects">();

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        stripePlugin<User, "analytics", "projects">({
          stripe: createStripeStub(),
          webhookSecret: "whsec_test",
          handlers: {
            customers: billing.customers,
            subscriptions: billing.subscriptions,
            events: billing.events,
          },
          plans: [
            {
              key: "starter",
              displayName: "Starter 1",
              scope: "user",
              prices: { monthly: { priceId: "price_1" } },
            },
            {
              key: "starter",
              displayName: "Starter 2",
              scope: "user",
              prices: { annual: { priceId: "price_2" } },
            },
          ] as const,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});

test("stripe plan scope must be compatible with customerMode", () => {
  const base = createBase();
  const billing = createStripeBillingStore<"analytics", "projects">();

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        stripePlugin<User, "analytics", "projects">({
          stripe: createStripeStub(),
          webhookSecret: "whsec_test",
          customerMode: "user",
          handlers: {
            customers: billing.customers,
            subscriptions: billing.subscriptions,
            events: billing.events,
          },
          plans: [
            {
              key: "team",
              displayName: "Team",
              scope: "organization",
              prices: { monthly: { priceId: "price_team" } },
            },
          ] as const,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});

test("stripe trial plans require valid trial settings and trial store", () => {
  const base = createBase();
  const billing = createStripeBillingStore<"analytics", "projects">();

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        stripePlugin<User, "analytics", "projects">({
          stripe: createStripeStub(),
          webhookSecret: "whsec_test",
          handlers: {
            customers: billing.customers,
            subscriptions: billing.subscriptions,
            events: billing.events,
          },
          plans: [
            {
              key: "starter",
              displayName: "Starter",
              scope: "user",
              prices: { monthly: { priceId: "price_1" } },
              trial: { days: 14 },
            },
          ] as const,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        stripePlugin<User, "analytics", "projects">({
          stripe: createStripeStub(),
          webhookSecret: "whsec_test",
          handlers: {
            customers: billing.customers,
            subscriptions: billing.subscriptions,
            events: billing.events,
            trials: billing.trials,
          },
          plans: [
            {
              key: "starter",
              displayName: "Starter",
              scope: "user",
              prices: { monthly: { priceId: "price_1" } },
              trial: { days: 0 },
            },
          ] as const,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});

test("stripe seats minimum cannot exceed maximum", () => {
  const base = createBase();
  const billing = createStripeBillingStore<"analytics", "projects">();

  assert.throws(() => {
    new OglofusAuth({
      adapters: base.adapters,
      plugins: [
        stripePlugin<User, "analytics", "projects">({
          stripe: createStripeStub(),
          webhookSecret: "whsec_test",
          handlers: {
            customers: billing.customers,
            subscriptions: billing.subscriptions,
            events: billing.events,
          },
          plans: [
            {
              key: "team",
              displayName: "Team",
              scope: "organization",
              prices: { monthly: { priceId: "price_team" } },
              seats: {
                enabled: true,
                minimum: 10,
                maximum: 5,
              },
            },
          ] as const,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});
