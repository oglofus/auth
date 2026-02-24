import test from "node:test";
import assert from "node:assert/strict";

import {
  OglofusAuth,
  organizationsPlugin,
  passwordPlugin,
  type MembershipAdapter,
  type OrganizationAdapter,
  type OrganizationEntitlementsAdapter,
  type OrganizationInviteAdapter,
  type OrganizationInviteDeliveryHandler,
  type PasswordCredentialAdapter,
  type UserBase,
  type OrganizationBase,
  type MembershipBase,
} from "../src/index.js";
import { createSessionStore, createUserStore } from "./helpers/in-memory.js";

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
        throw new Error("Organization not found");
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
    listByUser: async (userId) =>
      [...membershipsById.values()].filter((membership) => membership.userId === userId),
    listByOrganization: async (organizationId) =>
      [...membershipsById.values()].filter((membership) => membership.organizationId === organizationId),
    setRole: async (membershipId, role) => {
      const current = membershipsById.get(membershipId);
      if (!current) {
        throw new Error("Membership not found");
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
        throw new Error("Membership not found");
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
    membershipsById,
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

  const switched = await auth.setActiveOrganization(member.sessionId, created.data.organization.id);
  assert.equal(switched.ok, true);
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
