import test from "node:test";
import assert from "node:assert/strict";

import {
  OglofusAuth,
  organizationsPlugin,
  passwordPlugin,
  type AuthMethodPlugin,
  type UserBase,
} from "../src/index.js";
import { createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {}

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
          { id: string; organizationId: string; userId: string; role: "owner" | "member"; status: "active" | "invited" | "suspended"; createdAt: Date; updatedAt: Date },
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
