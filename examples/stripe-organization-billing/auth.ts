import Stripe from "stripe";

import {
  OglofusAuth,
  organizationsPlugin,
  passwordPlugin,
  stripePlugin,
  type MembershipAdapter,
  type MembershipBase,
  type OrganizationAdapter,
  type OrganizationBase,
  type OrganizationEntitlementsAdapter,
  type OrganizationInviteAdapter,
  type OrganizationInviteDeliveryHandler,
  type OrganizationSessionAdapter,
  type PasswordCredentialAdapter,
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

interface AppOrganization extends OrganizationBase {
  billing_email: string;
}

type Role = "owner" | "member";
type Permission = "members.manage" | "project.read";
type Feature = "sso";
type LimitKey = "seats";

interface Membership extends MembershipBase<Role> {}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

const usersById = new Map<string, AppUser>();
const sessionsById = new Map<string, Parameters<SessionAdapter["create"]>[0]>();
const orgsById = new Map<string, AppOrganization>();
const membershipsById = new Map<string, Membership>();
const featureOverrides = new Map<string, Partial<Record<Feature, boolean>>>();
const limitOverrides = new Map<string, Partial<Record<LimitKey, number>>>();
const passwordHashes = new Map<string, string>();
const customersBySubject = new Map<
  string,
  { id: string; subject: StripeSubject; stripeCustomerId: string; createdAt: Date; updatedAt: Date }
>();
const subscriptionsByStripeId = new Map<string, StripeSubscriptionSnapshot<Feature, LimitKey>>();
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

const organizationSessions: OrganizationSessionAdapter = {
  setActiveOrganization: async (sessionId, organizationId) => {
    const session = sessionsById.get(sessionId);
    if (!session) {
      return null;
    }
    const next = { ...session, activeOrganizationId: organizationId };
    sessionsById.set(sessionId, next);
    return next;
  },
};

const organizations: OrganizationAdapter<AppOrganization> = {
  create: async (input) => {
    const org: AppOrganization = {
      ...(input as AppOrganization),
      id: crypto.randomUUID(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    orgsById.set(org.id, org);
    return org;
  },
  findById: async (organizationId) => orgsById.get(organizationId) ?? null,
  findBySlug: async (slug) => [...orgsById.values()].find((org) => org.slug === slug) ?? null,
  update: async (organizationId, patch) => {
    const current = orgsById.get(organizationId);
    if (!current) {
      return null;
    }
    const next = { ...current, ...patch, updatedAt: new Date() };
    orgsById.set(organizationId, next);
    return next;
  },
};

const memberships: MembershipAdapter<Role, Membership> = {
  create: async (input) => {
    const membership: Membership = {
      ...(input as Membership),
      id: crypto.randomUUID(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    membershipsById.set(membership.id, membership);
    return membership;
  },
  findById: async (membershipId) => membershipsById.get(membershipId) ?? null,
  findByUserAndOrganization: async (userId, organizationId) =>
    [...membershipsById.values()].find(
      (membership) => membership.userId === userId && membership.organizationId === organizationId,
    ) ?? null,
  listByUser: async (userId) => [...membershipsById.values()].filter((membership) => membership.userId === userId),
  listByOrganization: async (organizationId) =>
    [...membershipsById.values()].filter((membership) => membership.organizationId === organizationId),
  setRole: async () => null,
  setStatus: async () => null,
  delete: async () => {},
};

const invites: OrganizationInviteAdapter<Role> = {
  create: async () => {},
  findActiveByTokenHash: async () => null,
  consume: async () => false,
  revoke: async () => {},
};

const inviteDelivery: OrganizationInviteDeliveryHandler<Role> = {
  send: async () => ({ accepted: true }),
};

const entitlements: OrganizationEntitlementsAdapter<Feature, LimitKey> = {
  getFeatureOverrides: async (organizationId) => featureOverrides.get(organizationId) ?? {},
  getLimitOverrides: async (organizationId) => limitOverrides.get(organizationId) ?? {},
  setFeatureOverride: async (organizationId, feature, enabled) => {
    featureOverrides.set(organizationId, {
      ...(featureOverrides.get(organizationId) ?? {}),
      [feature]: enabled,
    });
  },
  setLimitOverride: async (organizationId, key, value) => {
    limitOverrides.set(organizationId, {
      ...(limitOverrides.get(organizationId) ?? {}),
      [key]: value,
    });
  },
};

const credentials: PasswordCredentialAdapter = {
  getPasswordHash: async (userId) => passwordHashes.get(userId) ?? null,
  setPasswordHash: async (userId, passwordHash) => {
    passwordHashes.set(userId, passwordHash);
  },
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

const subscriptions: StripeSubscriptionAdapter<Feature, LimitKey> = {
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

export const auth = new OglofusAuth({
  adapters: { users, sessions },
  plugins: [
    passwordPlugin<AppUser, "given_name">({
      requiredProfileFields: ["given_name"] as const,
      credentials,
    }),
    stripePlugin<AppUser, Feature, LimitKey>({
      stripe,
      webhookSecret: process.env.STRIPE_WEBHOOK_SECRET!,
      customerMode: "organization",
      plans: [
        {
          key: "team",
          displayName: "Team",
          scope: "organization",
          prices: {
            monthly: { priceId: process.env.STRIPE_TEAM_MONTHLY_PRICE_ID! },
            annual: { priceId: process.env.STRIPE_TEAM_ANNUAL_PRICE_ID! },
          },
          seats: {
            enabled: true,
            minimum: 2,
            limitKey: "seats",
          },
          features: { sso: true },
          limits: { seats: 2 },
        },
      ] as const,
      handlers: {
        customers,
        subscriptions,
        events,
        trials,
      },
    }),
    organizationsPlugin<AppUser, AppOrganization, Role, Membership, Permission, Feature, LimitKey, "billing_email">({
      inviteBaseUrl: "https://app.example.com/invite",
      organizationRequiredFields: ["billing_email"] as const,
      handlers: {
        organizations,
        organizationSessions,
        memberships,
        invites,
        inviteDelivery,
        entitlements,
        roles: {
          owner: {
            permissions: ["members.manage", "project.read"],
            features: { sso: false },
            limits: { seats: 100 },
            system: { owner: true },
          },
          member: {
            permissions: ["project.read"],
            features: { sso: false },
            limits: { seats: 1 },
            system: { default: true },
          },
        },
        defaultRole: "member",
      },
    }),
  ] as const,
});
