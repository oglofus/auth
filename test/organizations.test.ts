import assert from "node:assert/strict";
import test from "node:test";

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
  type PasswordCredentialAdapter,
  type UserBase,
} from "../src/index.js";
import { createSessionStore, createStripeBillingStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

type OrgRole = "owner" | "member";
type OrgPermission = "members.manage" | "project.read";
type OrgFeature = "sso";
type OrgLimitKey = "seats";

interface Organization extends OrganizationBase {
  billing_email: string;
}

interface Membership extends MembershipBase<OrgRole> {}

const createOrgEnv = () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const organizationSessions = sessions.organizationAdapter;
  const passwordHashes = new Map<string, string>();

  const credentials: PasswordCredentialAdapter = {
    getPasswordHash: async (userId) => passwordHashes.get(userId) ?? null,
    setPasswordHash: async (userId, passwordHash) => {
      passwordHashes.set(userId, passwordHash);
    },
  };

  const organizationsById = new Map<string, Organization>();
  const organizationsBySlug = new Map<string, Organization>();
  const membershipsById = new Map<string, Membership>();
  const invitesById = new Map<
    string,
    {
      id: string;
      organizationId: string;
      email: string;
      role: OrgRole;
      tokenHash: string;
      invitedByUserId: string;
      expiresAt: Date;
      acceptedAt: Date | null;
      revokedAt: Date | null;
    }
  >();

  const featureOverrides = new Map<string, Partial<Record<OrgFeature, boolean>>>();
  const limitOverrides = new Map<string, Partial<Record<OrgLimitKey, number>>>();
  const deliveredLinks: string[] = [];

  const organizations: OrganizationAdapter<Organization> = {
    create: async (input) => {
      const organization: Organization = {
        ...input,
        id: crypto.randomUUID(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      organizationsById.set(organization.id, organization);
      organizationsBySlug.set(organization.slug, organization);
      return organization;
    },
    findById: async (organizationId) => organizationsById.get(organizationId) ?? null,
    findBySlug: async (slug) => organizationsBySlug.get(slug) ?? null,
    update: async (organizationId, patch) => {
      const current = organizationsById.get(organizationId);
      if (!current) {
        return null;
      }
      const next = {
        ...current,
        ...patch,
        updatedAt: new Date(),
      };
      organizationsById.set(organizationId, next);
      organizationsBySlug.set(next.slug, next);
      return next;
    },
  };

  const memberships: MembershipAdapter<OrgRole, Membership> = {
    create: async (input) => {
      const membership: Membership = {
        ...input,
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
    setRole: async (membershipId, role) => {
      const current = membershipsById.get(membershipId);
      if (!current) {
        return null;
      }
      const next = {
        ...current,
        role,
        updatedAt: new Date(),
      };
      membershipsById.set(membershipId, next);
      return next;
    },
    setStatus: async (membershipId, status) => {
      const current = membershipsById.get(membershipId);
      if (!current) {
        return null;
      }
      const next = {
        ...current,
        status,
        updatedAt: new Date(),
      };
      membershipsById.set(membershipId, next);
      return next;
    },
    delete: async (membershipId) => {
      membershipsById.delete(membershipId);
    },
  };

  const invites: OrganizationInviteAdapter<OrgRole> = {
    create: async (invite) => {
      invitesById.set(invite.id, invite);
    },
    findActiveByTokenHash: async (tokenHash) =>
      [...invitesById.values()].find(
        (invite) =>
          invite.tokenHash === tokenHash &&
          invite.acceptedAt === null &&
          invite.revokedAt === null &&
          invite.expiresAt.getTime() > Date.now(),
      ) ?? null,
    consume: async (inviteId) => {
      const current = invitesById.get(inviteId);
      if (!current || current.acceptedAt !== null || current.revokedAt !== null) {
        return false;
      }
      invitesById.set(inviteId, {
        ...current,
        acceptedAt: new Date(),
      });
      return true;
    },
    revoke: async (inviteId) => {
      const current = invitesById.get(inviteId);
      if (!current) {
        return;
      }
      invitesById.set(inviteId, {
        ...current,
        revokedAt: new Date(),
      });
    },
  };

  const inviteDelivery: OrganizationInviteDeliveryHandler<OrgRole> = {
    send: async (payload) => {
      deliveredLinks.push(payload.inviteLink);
      return {
        accepted: true,
        queuedAt: new Date(),
      };
    },
  };

  const entitlements: OrganizationEntitlementsAdapter<OrgFeature, OrgLimitKey> = {
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

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      passwordPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        credentials,
      }),
      organizationsPlugin<
        User,
        Organization,
        OrgRole,
        Membership,
        OrgPermission,
        OrgFeature,
        OrgLimitKey,
        "billing_email"
      >({
        inviteBaseUrl: "https://example.com/invite",
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
              features: { sso: true },
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
    validateConfigOnStart: true,
  });

  return {
    auth,
    deliveredLinks,
    organizationSessions,
    membershipsById,
    memberships,
    sessionsById: sessions.byId,
  };
};

test("organizations plugin supports create/invite/accept/check and session tenant switching", async () => {
  const { auth, deliveredLinks } = createOrgEnv();

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  assert.equal(owner.ok, true);
  if (!owner.ok) {
    return;
  }

  const member = await auth.register({
    method: "password",
    email: "member@example.com",
    password: "secret",
    given_name: "Member",
  });
  assert.equal(member.ok, true);
  if (!member.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );

  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const invited = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "member@example.com",
      role: "member",
    },
    { userId: owner.user.id },
  );

  assert.equal(invited.ok, true);
  assert.equal(deliveredLinks.length, 1);

  const inviteUrl = new URL(deliveredLinks[0]);
  const inviteToken = inviteUrl.searchParams.get("token");
  assert.equal(typeof inviteToken, "string");

  const accepted = await orgApi.acceptInvite({
    token: inviteToken!,
    userId: member.user.id,
  });

  assert.equal(accepted.ok, true);
  if (!accepted.ok) {
    return;
  }

  const canRead = await orgApi.checkPermission({
    organizationId: created.data.organization.id,
    userId: member.user.id,
    permission: "project.read",
  });
  assert.equal(canRead.ok, true);
  if (canRead.ok) {
    assert.equal(canRead.data.allowed, true);
  }

  const canManage = await orgApi.checkPermission({
    organizationId: created.data.organization.id,
    userId: member.user.id,
    permission: "members.manage",
  });
  assert.equal(canManage.ok, true);
  if (canManage.ok) {
    assert.equal(canManage.data.allowed, false);
  }

  const switched = await orgApi.setActiveOrganization({
    sessionId: member.sessionId,
    organizationId: created.data.organization.id,
  });
  assert.equal(switched.ok, true);
  if (!switched.ok) {
    return;
  }

  assert.equal(switched.data.activeOrganizationId, created.data.organization.id);

  const cleared = await orgApi.setActiveOrganization({
    sessionId: member.sessionId,
  });
  assert.equal(cleared.ok, true);
  if (cleared.ok) {
    assert.equal(cleared.data.activeOrganizationId, null);
  }
});

test("organizations last owner guard prevents demoting final owner", async () => {
  const { auth } = createOrgEnv();

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  assert.equal(owner.ok, true);
  if (!owner.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-last-owner",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const demote = await orgApi.setMemberRole(
    {
      organizationId: created.data.organization.id,
      membershipId: created.data.membership.id,
      role: "member",
    },
    { userId: owner.user.id },
  );

  assert.equal(demote.ok, false);
  if (!demote.ok) {
    assert.equal(demote.error.code, "LAST_OWNER_GUARD");
  }
});

test("organizations setActiveOrganization returns SESSION_NOT_FOUND when the session is missing", async () => {
  const { auth } = createOrgEnv();

  const result = await auth.method("organizations").setActiveOrganization({
    sessionId: "missing-session",
    organizationId: "org_123",
  });

  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.code, "SESSION_NOT_FOUND");
  }
});

test("organizations setActiveOrganization returns SESSION_NOT_FOUND when organization session update loses the session", async () => {
  const { auth, deliveredLinks, organizationSessions } = createOrgEnv();

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  assert.equal(owner.ok, true);
  if (!owner.ok) {
    return;
  }

  const member = await auth.register({
    method: "password",
    email: "member@example.com",
    password: "secret",
    given_name: "Member",
  });
  assert.equal(member.ok, true);
  if (!member.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-race-session",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const invited = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "member@example.com",
    },
    { userId: owner.user.id },
  );
  assert.equal(invited.ok, true);
  assert.equal(deliveredLinks.length, 1);

  const inviteToken = new URL(deliveredLinks[0]).searchParams.get("token");
  assert.equal(typeof inviteToken, "string");

  const accepted = await orgApi.acceptInvite({
    token: inviteToken!,
    userId: member.user.id,
  });
  assert.equal(accepted.ok, true);
  if (!accepted.ok) {
    return;
  }

  organizationSessions.setActiveOrganization = async () => undefined;

  const switched = await orgApi.setActiveOrganization({
    sessionId: member.sessionId,
    organizationId: created.data.organization.id,
  });

  assert.equal(switched.ok, false);
  if (!switched.ok) {
    assert.equal(switched.error.code, "SESSION_NOT_FOUND");
  }
});

test("organizations acceptInvite returns MEMBERSHIP_NOT_FOUND when activating an existing membership fails", async () => {
  const { auth, deliveredLinks, memberships } = createOrgEnv();

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  assert.equal(owner.ok, true);
  if (!owner.ok) {
    return;
  }

  const member = await auth.register({
    method: "password",
    email: "member@example.com",
    password: "secret",
    given_name: "Member",
  });
  assert.equal(member.ok, true);
  if (!member.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-null-status",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const existingMembership = await memberships.create({
    organizationId: created.data.organization.id,
    userId: member.user.id,
    role: "member",
    status: "suspended",
  });

  const invited = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "member@example.com",
      role: "member",
    },
    { userId: owner.user.id },
  );
  assert.equal(invited.ok, true);
  assert.equal(deliveredLinks.length, 1);

  memberships.setStatus = async (membershipId, status) => {
    assert.equal(membershipId, existingMembership.id);
    assert.equal(status, "active");
    return undefined;
  };

  const accepted = await orgApi.acceptInvite({
    token: new URL(deliveredLinks[0]).searchParams.get("token")!,
    userId: member.user.id,
  });

  assert.equal(accepted.ok, false);
  if (!accepted.ok) {
    assert.equal(accepted.error.code, "MEMBERSHIP_NOT_FOUND");
  }
});

test("organizations setMemberRole returns MEMBERSHIP_NOT_FOUND when membership mutation returns nullish", async () => {
  const { auth, deliveredLinks, memberships } = createOrgEnv();

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  assert.equal(owner.ok, true);
  if (!owner.ok) {
    return;
  }

  const member = await auth.register({
    method: "password",
    email: "member@example.com",
    password: "secret",
    given_name: "Member",
  });
  assert.equal(member.ok, true);
  if (!member.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-null-role",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const invited = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "member@example.com",
      role: "member",
    },
    { userId: owner.user.id },
  );
  assert.equal(invited.ok, true);
  assert.equal(deliveredLinks.length, 1);

  const accepted = await orgApi.acceptInvite({
    token: new URL(deliveredLinks[0]).searchParams.get("token")!,
    userId: member.user.id,
  });
  assert.equal(accepted.ok, true);
  if (!accepted.ok) {
    return;
  }

  memberships.setRole = async () => undefined;

  const updated = await orgApi.setMemberRole(
    {
      organizationId: created.data.organization.id,
      membershipId: accepted.data.membership.id,
      role: "member",
    },
    { userId: owner.user.id },
  );

  assert.equal(updated.ok, false);
  if (!updated.ok) {
    assert.equal(updated.error.code, "MEMBERSHIP_NOT_FOUND");
  }
});

test("organizations enforce owner-only invite and entitlement override actions", async () => {
  const { auth, deliveredLinks } = createOrgEnv();

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  const member = await auth.register({
    method: "password",
    email: "member@example.com",
    password: "secret",
    given_name: "Member",
  });
  assert.equal(owner.ok, true);
  assert.equal(member.ok, true);
  if (!owner.ok || !member.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-owner-only",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const invite = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "member@example.com",
    },
    { userId: owner.user.id },
  );
  assert.equal(invite.ok, true);
  if (!invite.ok) {
    return;
  }

  const accepted = await orgApi.acceptInvite({
    token: new URL(deliveredLinks[0]!).searchParams.get("token")!,
    userId: member.user.id,
  });
  assert.equal(accepted.ok, true);

  const memberInvite = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "third@example.com",
    },
    { userId: member.user.id },
  );
  assert.equal(memberInvite.ok, false);
  if (!memberInvite.ok) {
    assert.equal(memberInvite.error.code, "MEMBERSHIP_FORBIDDEN");
  }

  const featureOverride = await orgApi.setFeatureOverride(
    {
      organizationId: created.data.organization.id,
      feature: "sso",
      enabled: false,
    },
    { userId: member.user.id },
  );
  assert.equal(featureOverride.ok, false);
  if (!featureOverride.ok) {
    assert.equal(featureOverride.error.code, "MEMBERSHIP_FORBIDDEN");
  }

  const limitOverride = await orgApi.setLimitOverride(
    {
      organizationId: created.data.organization.id,
      key: "seats",
      value: 3,
    },
    { userId: member.user.id },
  );
  assert.equal(limitOverride.ok, false);
  if (!limitOverride.ok) {
    assert.equal(limitOverride.error.code, "MEMBERSHIP_FORBIDDEN");
  }
});

test("organizations validate active membership, invite email match, roles, permissions, and limits", async () => {
  const { auth, deliveredLinks } = createOrgEnv();

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  const member = await auth.register({
    method: "password",
    email: "member@example.com",
    password: "secret",
    given_name: "Member",
  });
  const outsider = await auth.register({
    method: "password",
    email: "outsider@example.com",
    password: "secret",
    given_name: "Outsider",
  });
  assert.equal(owner.ok, true);
  assert.equal(member.ok, true);
  assert.equal(outsider.ok, true);
  if (!owner.ok || !member.ok || !outsider.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-validation",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const noMembership = await orgApi.setActiveOrganization({
    sessionId: outsider.sessionId,
    organizationId: created.data.organization.id,
  });
  assert.equal(noMembership.ok, false);
  if (!noMembership.ok) {
    assert.equal(noMembership.error.code, "MEMBERSHIP_FORBIDDEN");
  }

  const invalidInviteRole = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "member@example.com",
      role: "admin" as OrgRole,
    },
    { userId: owner.user.id },
  );
  assert.equal(invalidInviteRole.ok, false);
  if (!invalidInviteRole.ok) {
    assert.equal(invalidInviteRole.error.code, "ROLE_INVALID");
  }

  const invited = await orgApi.inviteMember(
    {
      organizationId: created.data.organization.id,
      email: "member@example.com",
      role: "member",
    },
    { userId: owner.user.id },
  );
  assert.equal(invited.ok, true);
  if (!invited.ok) {
    return;
  }

  const mismatched = await orgApi.acceptInvite({
    token: new URL(deliveredLinks[0]!).searchParams.get("token")!,
    userId: outsider.user.id,
  });
  assert.equal(mismatched.ok, false);
  if (!mismatched.ok) {
    assert.equal(mismatched.error.code, "MEMBERSHIP_FORBIDDEN");
  }

  const accepted = await orgApi.acceptInvite({
    token: new URL(deliveredLinks[0]!).searchParams.get("token")!,
    userId: member.user.id,
  });
  assert.equal(accepted.ok, true);
  if (!accepted.ok) {
    return;
  }

  const invalidSetRole = await orgApi.setMemberRole(
    {
      organizationId: created.data.organization.id,
      membershipId: accepted.data.membership.id,
      role: "admin" as OrgRole,
    },
    { userId: owner.user.id },
  );
  assert.equal(invalidSetRole.ok, false);
  if (!invalidSetRole.ok) {
    assert.equal(invalidSetRole.error.code, "ROLE_INVALID");
  }

  const permission = await orgApi.checkPermission({
    organizationId: created.data.organization.id,
    userId: member.user.id,
    permission: "members.manage",
  });
  assert.equal(permission.ok, true);
  if (permission.ok) {
    assert.equal(permission.data.allowed, false);
    assert.equal(permission.data.reason, "permission_denied");
  }

  const limit = await orgApi.checkLimit({
    organizationId: created.data.organization.id,
    userId: member.user.id,
    key: "seats",
    amount: 2,
  });
  assert.equal(limit.ok, true);
  if (limit.ok) {
    assert.equal(limit.data.allowed, false);
    assert.equal(limit.data.remaining, -1);
  }
});

test("organizations propagate stripe entitlement errors", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const organizationSessions = sessions.organizationAdapter;
  const billing = createStripeBillingStore<OrgFeature, OrgLimitKey>();
  const passwordHashes = new Map<string, string>();
  const organizationsById = new Map<string, Organization>();
  const organizationsBySlug = new Map<string, Organization>();
  const membershipsById = new Map<string, Membership>();

  const credentials: PasswordCredentialAdapter = {
    getPasswordHash: async (userId) => passwordHashes.get(userId) ?? null,
    setPasswordHash: async (userId, passwordHash) => {
      passwordHashes.set(userId, passwordHash);
    },
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      passwordPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        credentials,
      }),
      stripePlugin<User, OrgFeature, OrgLimitKey>({
        stripe: {
          webhooks: new Stripe("sk_test_123").webhooks,
          customers: { create: async () => ({ id: "cus_user" }) },
          checkout: { sessions: { create: async () => ({ id: "cs_user", url: "https://checkout" }) } },
          billingPortal: { sessions: { create: async () => ({ url: "https://billing" }) } },
          subscriptions: {
            retrieve: async () => {
              throw new Error("not used");
            },
            update: async () => {
              throw new Error("not used");
            },
            cancel: async () => {
              throw new Error("not used");
            },
          },
          subscriptionSchedules: {
            create: async () => ({ id: "sched_1" }),
          },
        } as unknown as Stripe,
        webhookSecret: "whsec_test",
        customerMode: "user",
        plans: [
          {
            key: "starter",
            displayName: "Starter",
            scope: "user",
            prices: {
              monthly: { priceId: "price_starter" },
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
      organizationsPlugin<
        User,
        Organization,
        OrgRole,
        Membership,
        OrgPermission,
        OrgFeature,
        OrgLimitKey,
        "billing_email"
      >({
        inviteBaseUrl: "https://example.com/invite",
        organizationRequiredFields: ["billing_email"] as const,
        handlers: {
          organizations: {
            create: async (input) => {
              const organization: Organization = {
                ...input,
                id: crypto.randomUUID(),
                createdAt: new Date(),
                updatedAt: new Date(),
              };
              organizationsById.set(organization.id, organization);
              organizationsBySlug.set(organization.slug, organization);
              return organization;
            },
            findById: async (organizationId) => organizationsById.get(organizationId) ?? null,
            findBySlug: async (slug) => organizationsBySlug.get(slug) ?? null,
            update: async () => null,
          },
          organizationSessions,
          memberships: {
            create: async (input) => {
              const membership: Membership = {
                ...input,
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
            listByUser: async (userId) =>
              [...membershipsById.values()].filter((membership) => membership.userId === userId),
            listByOrganization: async (organizationId) =>
              [...membershipsById.values()].filter((membership) => membership.organizationId === organizationId),
            setRole: async () => null,
            setStatus: async () => null,
            delete: async () => {},
          },
          invites: {
            create: async () => {},
            findActiveByTokenHash: async () => null,
            consume: async () => false,
            revoke: async () => {},
          },
          inviteDelivery: {
            send: async () => ({
              accepted: true,
              queuedAt: new Date(),
            }),
          },
          entitlements: {
            getFeatureOverrides: async () => ({}),
            getLimitOverrides: async () => ({}),
            setFeatureOverride: async () => {},
            setLimitOverride: async () => {},
          },
          roles: {
            owner: {
              permissions: ["members.manage", "project.read"],
              system: { owner: true },
            },
            member: {
              permissions: ["project.read"],
              system: { default: true },
            },
          },
          defaultRole: "member",
        },
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const owner = await auth.register({
    method: "password",
    email: "owner@example.com",
    password: "secret",
    given_name: "Owner",
  });
  assert.equal(owner.ok, true);
  if (!owner.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-stripe-error",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  const result = await orgApi.getEntitlements({
    organizationId: created.data.organization.id,
    userId: owner.user.id,
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.code, "INVALID_INPUT");
  }
});

test("organizations merge stripe entitlements before manual overrides", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const organizationSessions = sessions.organizationAdapter;
  const billing = createStripeBillingStore<OrgFeature, OrgLimitKey>();
  const passwordHashes = new Map<string, string>();

  const credentials: PasswordCredentialAdapter = {
    getPasswordHash: async (userId) => passwordHashes.get(userId) ?? null,
    setPasswordHash: async (userId, passwordHash) => {
      passwordHashes.set(userId, passwordHash);
    },
  };

  const organizationsById = new Map<string, Organization>();
  const organizationsBySlug = new Map<string, Organization>();
  const membershipsById = new Map<string, Membership>();
  const featureOverrides = new Map<string, Partial<Record<OrgFeature, boolean>>>();
  const limitOverrides = new Map<string, Partial<Record<OrgLimitKey, number>>>();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      passwordPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        credentials,
      }),
      stripePlugin<User, OrgFeature, OrgLimitKey>({
        stripe: {
          webhooks: new Stripe("sk_test_123").webhooks,
          customers: { create: async () => ({ id: "cus_org" }) },
          checkout: { sessions: { create: async () => ({ id: "cs_org", url: "https://checkout" }) } },
          billingPortal: { sessions: { create: async () => ({ url: "https://billing" }) } },
          subscriptions: {
            retrieve: async () => {
              throw new Error("not used");
            },
            update: async () => {
              throw new Error("not used");
            },
            cancel: async () => {
              throw new Error("not used");
            },
          },
          subscriptionSchedules: {
            create: async () => ({ id: "sched_1" }),
          },
        } as unknown as Stripe,
        webhookSecret: "whsec_test",
        customerMode: "organization",
        plans: [
          {
            key: "team",
            displayName: "Team",
            scope: "organization",
            prices: {
              monthly: { priceId: "price_team" },
            },
            seats: {
              enabled: true,
              limitKey: "seats",
            },
            features: {
              sso: true,
            },
            limits: {
              seats: 10,
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
      organizationsPlugin<
        User,
        Organization,
        OrgRole,
        Membership,
        OrgPermission,
        OrgFeature,
        OrgLimitKey,
        "billing_email"
      >({
        inviteBaseUrl: "https://example.com/invite",
        organizationRequiredFields: ["billing_email"] as const,
        handlers: {
          organizations: {
            create: async (input) => {
              const organization: Organization = {
                ...input,
                id: crypto.randomUUID(),
                createdAt: new Date(),
                updatedAt: new Date(),
              };
              organizationsById.set(organization.id, organization);
              organizationsBySlug.set(organization.slug, organization);
              return organization;
            },
            findById: async (organizationId) => organizationsById.get(organizationId) ?? null,
            findBySlug: async (slug) => organizationsBySlug.get(slug) ?? null,
            update: async (organizationId, patch) => {
              const current = organizationsById.get(organizationId);
              if (!current) {
                return null;
              }
              const next = { ...current, ...patch, updatedAt: new Date() };
              organizationsById.set(organizationId, next);
              organizationsBySlug.set(next.slug, next);
              return next;
            },
          },
          organizationSessions,
          memberships: {
            create: async (input) => {
              const membership: Membership = {
                ...input,
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
            listByUser: async (userId) =>
              [...membershipsById.values()].filter((membership) => membership.userId === userId),
            listByOrganization: async (organizationId) =>
              [...membershipsById.values()].filter((membership) => membership.organizationId === organizationId),
            setRole: async () => null,
            setStatus: async () => null,
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
          },
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
    validateConfigOnStart: true,
  });

  const owner = await auth.register({
    method: "password",
    email: "owner@acme.com",
    password: "secret",
    given_name: "Owner",
  });
  assert.equal(owner.ok, true);
  if (!owner.ok) {
    return;
  }

  const orgApi = auth.method("organizations");
  const created = await orgApi.createOrganization(
    {
      name: "Acme",
      slug: "acme-striped",
      profile: { billing_email: "billing@acme.com" },
    },
    { userId: owner.user.id },
  );
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }

  await billing.subscriptions.upsert({
    id: crypto.randomUUID(),
    subject: { kind: "organization", organizationId: created.data.organization.id },
    stripeCustomerId: "cus_org",
    stripeSubscriptionId: "sub_org",
    stripePriceId: "price_team",
    planKey: "team",
    status: "active",
    billingCycle: "monthly",
    seats: 5,
    cancelAtPeriodEnd: false,
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(),
    trialStartedAt: null,
    trialEndsAt: null,
    canceledAt: null,
    features: { sso: true },
    limits: { seats: 5 },
    metadata: {},
    updatedAt: new Date(),
  });

  const merged = await orgApi.getEntitlements({
    organizationId: created.data.organization.id,
    userId: owner.user.id,
  });
  assert.equal(merged.ok, true);
  if (merged.ok) {
    assert.equal(merged.data.features.sso, true);
    assert.equal(merged.data.limits.seats, 5);
  }

  await orgApi.setFeatureOverride(
    {
      organizationId: created.data.organization.id,
      feature: "sso",
      enabled: false,
    },
    { userId: owner.user.id },
  );
  await orgApi.setLimitOverride(
    {
      organizationId: created.data.organization.id,
      key: "seats",
      value: 2,
    },
    { userId: owner.user.id },
  );

  const overridden = await orgApi.getEntitlements({
    organizationId: created.data.organization.id,
    userId: owner.user.id,
  });
  assert.equal(overridden.ok, true);
  if (overridden.ok) {
    assert.equal(overridden.data.features.sso, false);
    assert.equal(overridden.data.limits.seats, 2);
  }
});
