import test from "node:test";
import assert from "node:assert/strict";
import { OAuth2Tokens } from "arctic";

import {
  OglofusAuth,
  oauth2Plugin,
  type OAuth2AccountAdapter,
  type UserBase,
} from "../src/index.js";
import {
  createIdempotencyStore,
  createPendingProfileStore,
  createSessionStore,
  createUserStore,
} from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
  family_name: string;
}

const createTokens = () =>
  new OAuth2Tokens({
    access_token: "access-token",
    refresh_token: "refresh-token",
    token_type: "bearer",
  });

test("oauth2 missing fields returns PROFILE_COMPLETION_REQUIRED and completeProfile links the account before consume", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const pending = createPendingProfileStore<User>();
  const order: string[] = [];
  const redirectUris: string[] = [];

  const originalConsume = pending.adapter.consume;
  pending.adapter.consume = async (pendingProfileId) => {
    order.push("consume");
    return originalConsume(pendingProfileId);
  };

  const linkedAccounts = new Map<string, string>();
  const accounts: OAuth2AccountAdapter<"google"> = {
    findUserId: async (provider, providerUserId) =>
      linkedAccounts.get(`${provider}:${providerUserId}`),
    linkAccount: async (input) => {
      order.push("linkAccount");
      linkedAccounts.set(`${input.provider}:${input.providerUserId}`, input.userId);
    },
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      pendingProfiles: pending.adapter,
    },
    plugins: [
      oauth2Plugin<User, "google", "given_name" | "family_name">({
        providers: {
          google: {
            exchangeAuthorizationCode: async (input) => {
              redirectUris.push(input.redirectUri);
              return createTokens();
            },
            resolveProfile: async () => ({
              providerUserId: "google-user-1",
              email: "nikos@example.com",
              emailVerified: true,
              profile: {
                given_name: "Nikos",
              },
            }),
          },
        },
        accounts,
        requiredProfileFields: ["given_name", "family_name"] as const,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const step1 = await auth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: "code",
    redirectUri: "https://example.com/callback",
    codeVerifier: "code-verifier",
  });

  assert.equal(step1.ok, false);
  if (step1.ok) {
    return;
  }

  assert.equal(step1.error.code, "PROFILE_COMPLETION_REQUIRED");
  const pendingProfileId = String(step1.error.meta?.pendingProfileId ?? "");
  assert.ok(pendingProfileId.length > 0);

  const step2 = await auth.completeProfile({
    pendingProfileId,
    profile: {
      given_name: "Nikos",
      family_name: "Gram",
    },
  });

  assert.equal(step2.ok, true);
  if (!step2.ok) {
    return;
  }

  assert.equal(step2.user.email, "nikos@example.com");
  assert.equal(step2.user.family_name, "Gram");
  assert.equal(linkedAccounts.get("google:google-user-1"), step2.user.id);
  assert.equal(pending.byId.get(pendingProfileId)?.consumedAt instanceof Date, true);
  assert.deepEqual(order, ["linkAccount", "consume"]);
  assert.deepEqual(redirectUris, ["https://example.com/callback"]);
});

test("completeProfile leaves pending profile reusable when oauth account linking fails", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const pending = createPendingProfileStore<User>();

  let shouldFailLink = true;
  const linkedAccounts = new Map<string, string>();
  const accounts: OAuth2AccountAdapter<"google"> = {
    findUserId: async (provider, providerUserId) =>
      linkedAccounts.get(`${provider}:${providerUserId}`),
    linkAccount: async (input) => {
      if (shouldFailLink) {
        throw new Error("link failed");
      }

      linkedAccounts.set(`${input.provider}:${input.providerUserId}`, input.userId);
    },
  };

  await pending.adapter.create({
    pendingProfileId: "pending_123",
    sourceMethod: "oauth2",
    email: "nikos@example.com",
    missingFields: ["family_name"],
    prefill: {
      given_name: "Nikos",
      emailVerified: true,
    },
    continuation: {
      provider: "google",
      providerUserId: "google-user-1",
      accessToken: "access-token",
      refreshToken: "refresh-token",
    },
    expiresAt: new Date(Date.now() + 60_000),
    consumedAt: null,
  });

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      pendingProfiles: pending.adapter,
    },
    plugins: [
      oauth2Plugin<User, "google", "given_name" | "family_name">({
        providers: {
          google: {
            exchangeAuthorizationCode: async () => createTokens(),
            resolveProfile: async () => ({
              providerUserId: "google-user-1",
              email: "nikos@example.com",
              emailVerified: true,
              profile: {
                given_name: "Nikos",
                family_name: "Gram",
              },
            }),
          },
        },
        accounts,
        requiredProfileFields: ["given_name", "family_name"] as const,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const failed = await auth.completeProfile({
    pendingProfileId: "pending_123",
    profile: {
      family_name: "Gram",
    },
  });

  assert.equal(failed.ok, false);
  if (!failed.ok) {
    assert.equal(failed.error.code, "INTERNAL_ERROR");
  }
  assert.equal(pending.byId.get("pending_123")?.consumedAt, null);

  shouldFailLink = false;

  const retried = await auth.completeProfile({
    pendingProfileId: "pending_123",
    profile: {
      family_name: "Gram",
    },
  });

  assert.equal(retried.ok, true);
  if (!retried.ok) {
    return;
  }

  assert.equal(linkedAccounts.get("google:google-user-1"), retried.user.id);
  assert.equal(pending.byId.get("pending_123")?.consumedAt instanceof Date, true);
});

test("oauth2 duplicate callback with the same idempotency key returns conflict", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const idempotency = createIdempotencyStore();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      idempotency: idempotency.adapter,
    },
    plugins: [
      oauth2Plugin<User, "google", never>({
        providers: {
          google: {
            exchangeAuthorizationCode: async () => createTokens(),
            resolveProfile: async () => ({
              providerUserId: "google-user-1",
              email: "nikos@example.com",
              emailVerified: true,
              profile: {},
            }),
          },
        },
        accounts: {
          findUserId: async () => null,
          linkAccount: async () => {},
        },
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const first = await auth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: "code-1",
    redirectUri: "https://example.com/callback",
    codeVerifier: "code-verifier",
    idempotencyKey: "state-123",
  });
  assert.equal(first.ok, true);

  const duplicate = await auth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: "code-1",
    redirectUri: "https://example.com/callback",
    codeVerifier: "code-verifier",
    idempotencyKey: "state-123",
  });

  assert.equal(duplicate.ok, false);
  if (!duplicate.ok) {
    assert.equal(duplicate.error.code, "CONFLICT");
  }
});

test("oauth2 requires idempotencyKey when idempotency adapter is configured", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const idempotency = createIdempotencyStore();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      idempotency: idempotency.adapter,
    },
    plugins: [
      oauth2Plugin<User, "google", never>({
        providers: {
          google: {
            exchangeAuthorizationCode: async () => createTokens(),
            resolveProfile: async () => ({
              providerUserId: "google-user-1",
              email: "nikos@example.com",
              emailVerified: true,
              profile: {},
            }),
          },
        },
        accounts: {
          findUserId: async () => null,
          linkAccount: async () => {},
        },
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const result = await auth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: "code-1",
    redirectUri: "https://example.com/callback",
    codeVerifier: "code-verifier",
  });

  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.code, "INVALID_INPUT");
  }
});
