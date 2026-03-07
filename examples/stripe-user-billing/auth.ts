import Stripe from "stripe";

import {
  OglofusAuth,
  stripePlugin,
  type SessionAdapter,
  type StripeCustomerAdapter,
  type StripeSubject,
  type StripeSubscriptionAdapter,
  type StripeSubscriptionSnapshot,
  type StripeTrialUsageAdapter,
  type StripeWebhookEventAdapter,
  type UserAdapter,
  type UserBase,
} from "@oglofus/auth";

interface AppUser extends UserBase {
  given_name: string;
}

type BillingFeature = "analytics";
type BillingLimit = "projects";

const usersById = new Map<string, AppUser>();
const sessionsById = new Map<string, Parameters<SessionAdapter["create"]>[0]>();
const customersBySubject = new Map<
  string,
  { id: string; subject: StripeSubject; stripeCustomerId: string; createdAt: Date; updatedAt: Date }
>();
const subscriptionsByStripeId = new Map<string, StripeSubscriptionSnapshot<BillingFeature, BillingLimit>>();
const processedEvents = new Set<string>();
const trialUsage = new Set<string>();

const subjectKey = (subject: StripeSubject) =>
  subject.kind === "user" ? `user:${subject.userId}` : `organization:${subject.organizationId}`;

const users: UserAdapter<AppUser> = {
  findById: async (id) => usersById.get(id) ?? null,
  findByEmail: async (email) => [...usersById.values()].find((user) => user.email === email) ?? null,
  create: async (input) => {
    const user: AppUser = {
      ...(input as AppUser),
      id: crypto.randomUUID(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    usersById.set(user.id, user);
    return user;
  },
  update: async (id, patch) => {
    const current = usersById.get(id);
    if (!current) {
      return null;
    }
    const next = { ...current, ...patch, updatedAt: new Date() };
    usersById.set(id, next);
    return next;
  },
};

const sessions: SessionAdapter = {
  create: async (session) => {
    sessionsById.set(session.id, session);
  },
  findById: async (id) => sessionsById.get(id) ?? null,
  revoke: async () => {},
  revokeAllForUser: async () => {},
};

const customers: StripeCustomerAdapter = {
  findBySubject: async (subject) => customersBySubject.get(subjectKey(subject)) ?? null,
  findByStripeCustomerId: async (stripeCustomerId) =>
    [...customersBySubject.values()].find((record) => record.stripeCustomerId === stripeCustomerId) ?? null,
  create: async (record) => {
    customersBySubject.set(subjectKey(record.subject), record);
  },
  updateByStripeCustomerId: async () => {},
};

const subscriptions: StripeSubscriptionAdapter<BillingFeature, BillingLimit> = {
  findActiveBySubject: async (subject) =>
    [...subscriptionsByStripeId.values()].find(
      (snapshot) => subjectKey(snapshot.subject) === subjectKey(subject) && snapshot.status !== "canceled",
    ) ?? null,
  findByStripeSubscriptionId: async (stripeSubscriptionId) => subscriptionsByStripeId.get(stripeSubscriptionId) ?? null,
  listBySubject: async (subject) =>
    [...subscriptionsByStripeId.values()].filter((snapshot) => subjectKey(snapshot.subject) === subjectKey(subject)),
  upsert: async (snapshot) => {
    subscriptionsByStripeId.set(snapshot.stripeSubscriptionId, snapshot);
  },
};

const events: StripeWebhookEventAdapter = {
  hasProcessed: async (eventId) => processedEvents.has(eventId),
  markProcessed: async ({ eventId }) => {
    processedEvents.add(eventId);
  },
};

const trials: StripeTrialUsageAdapter = {
  hasUsedTrial: async ({ subject, planKey }) => trialUsage.has(`${subjectKey(subject)}:${planKey}`),
  markUsedTrial: async ({ subject, planKey }) => {
    trialUsage.add(`${subjectKey(subject)}:${planKey}`);
  },
};

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export const auth = new OglofusAuth({
  adapters: { users, sessions },
  plugins: [
    stripePlugin<AppUser, BillingFeature, BillingLimit>({
      stripe,
      webhookSecret: process.env.STRIPE_WEBHOOK_SECRET!,
      customerMode: "user",
      plans: [
        {
          key: "starter",
          displayName: "Starter",
          scope: "user",
          prices: {
            monthly: { priceId: process.env.STRIPE_STARTER_MONTHLY_PRICE_ID! },
            annual: { priceId: process.env.STRIPE_STARTER_ANNUAL_PRICE_ID! },
          },
          trial: { days: 14 },
          features: { analytics: true },
          limits: { projects: 3 },
        },
      ] as const,
      handlers: {
        customers,
        subscriptions,
        events,
        trials,
      },
    }),
  ] as const,
});
