import { OAuth2Tokens } from "arctic";
import assert from "node:assert/strict";
import test from "node:test";

import { OglofusAuth, oauth2Plugin, type OAuth2AccountAdapter, type UserBase } from "../src/index.js";
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
    findUserId: async (provider, providerUserId) => linkedAccounts.get(`${provider}:${providerUserId}`),
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
    findUserId: async (provider, providerUserId) => linkedAccounts.get(`${provider}:${providerUserId}`),
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

test("oauth2 rejects disabled providers, missing PKCE, and missing email", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      oauth2Plugin<User, "google" | "github", never>({
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

  const disabled = await auth.authenticate({
    method: "oauth2",
    provider: "github",
    authorizationCode: "code",
    redirectUri: "https://example.com/callback",
    codeVerifier: "verifier",
  });
  assert.equal(disabled.ok, false);
  if (!disabled.ok) {
    assert.equal(disabled.error.code, "OAUTH2_PROVIDER_DISABLED");
  }

  const missingPkce = await auth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: "code",
    redirectUri: "https://example.com/callback",
  });
  assert.equal(missingPkce.ok, false);
  if (!missingPkce.ok) {
    assert.equal(missingPkce.error.code, "INVALID_INPUT");
  }

  const missingEmailAuth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      oauth2Plugin<User, "google", never>({
        providers: {
          google: {
            exchangeAuthorizationCode: async () => createTokens(),
            resolveProfile: async () => ({
              providerUserId: "google-user-2",
              email: "",
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

  const missingEmail = await missingEmailAuth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: "code",
    redirectUri: "https://example.com/callback",
    codeVerifier: "verifier",
  });
  assert.equal(missingEmail.ok, false);
  if (!missingEmail.ok) {
    assert.equal(missingEmail.error.code, "INVALID_INPUT");
  }
});

test("oauth2 partial profiles require the pendingProfiles adapter", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      oauth2Plugin<User, "google", "family_name">({
        providers: {
          google: {
            exchangeAuthorizationCode: async () => createTokens(),
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
        accounts: {
          findUserId: async () => null,
          linkAccount: async () => {},
        },
        requiredProfileFields: ["family_name"] as const,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const result = await auth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: "code",
    redirectUri: "https://example.com/callback",
    codeVerifier: "verifier",
  });

  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.code, "PLUGIN_MISCONFIGURED");
  }
});

test("completeProfile validates adapter presence, expiry, and required fields", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();

  const missingAdapterAuth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [] as const,
    validateConfigOnStart: true,
  });

  const missingAdapter = await missingAdapterAuth.completeProfile({
    pendingProfileId: "pending_missing",
    profile: {
      family_name: "Gram",
    },
  });
  assert.equal(missingAdapter.ok, false);
  if (!missingAdapter.ok) {
    assert.equal(missingAdapter.error.code, "PLUGIN_MISCONFIGURED");
  }

  const pending = createPendingProfileStore<User>();
  await pending.adapter.create({
    pendingProfileId: "pending_expired",
    sourceMethod: "oauth2",
    email: "nikos@example.com",
    missingFields: ["family_name"],
    prefill: {
      given_name: "Nikos",
      emailVerified: true,
    },
    continuation: null,
    expiresAt: new Date(Date.now() - 60_000),
    consumedAt: null,
  });
  await pending.adapter.create({
    pendingProfileId: "pending_consumed",
    sourceMethod: "oauth2",
    email: "nikos@example.com",
    missingFields: ["family_name"],
    prefill: {
      given_name: "Nikos",
      emailVerified: true,
    },
    continuation: null,
    expiresAt: new Date(Date.now() + 60_000),
    consumedAt: new Date(),
  });
  await pending.adapter.create({
    pendingProfileId: "pending_required",
    sourceMethod: "oauth2",
    email: "nikos@example.com",
    missingFields: ["family_name"],
    prefill: {
      given_name: "Nikos",
      emailVerified: true,
    },
    continuation: null,
    expiresAt: new Date(Date.now() + 60_000),
    consumedAt: null,
  });

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      pendingProfiles: pending.adapter,
    },
    plugins: [] as const,
    validateConfigOnStart: true,
  });

  const expired = await auth.completeProfile({
    pendingProfileId: "pending_expired",
    profile: {
      family_name: "Gram",
    },
  });
  assert.equal(expired.ok, false);
  if (!expired.ok) {
    assert.equal(expired.error.code, "PROFILE_COMPLETION_EXPIRED");
  }

  const consumed = await auth.completeProfile({
    pendingProfileId: "pending_consumed",
    profile: {
      family_name: "Gram",
    },
  });
  assert.equal(consumed.ok, false);
  if (!consumed.ok) {
    assert.equal(consumed.error.code, "PROFILE_COMPLETION_EXPIRED");
  }

  const required = await auth.completeProfile({
    pendingProfileId: "pending_required",
    profile: {},
  });
  assert.equal(required.ok, false);
  if (!required.ok) {
    assert.equal(required.error.code, "INVALID_INPUT");
  }
});

test("completeProfile requires a plugin continuation handler when continuation metadata exists", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const pending = createPendingProfileStore<User>();

  await pending.adapter.create({
    pendingProfileId: "pending_oauth",
    sourceMethod: "oauth2",
    email: "nikos@example.com",
    missingFields: [],
    prefill: {
      given_name: "Nikos",
      family_name: "Gram",
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
    plugins: [] as const,
    validateConfigOnStart: true,
  });

  const result = await auth.completeProfile({
    pendingProfileId: "pending_oauth",
    profile: {},
  });

  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.code, "PLUGIN_MISCONFIGURED");
  }
});

test("completeProfile surfaces consume races and updates existing users by email", async () => {
  const users = createUserStore<User>([
    {
      id: "user_existing",
      email: "nikos@example.com",
      emailVerified: false,
      given_name: "Old",
      family_name: "Name",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ]);
  const sessions = createSessionStore();
  const pending = createPendingProfileStore<User>();

  await pending.adapter.create({
    pendingProfileId: "pending_race",
    sourceMethod: "oauth2",
    email: "new@example.com",
    missingFields: [],
    prefill: {
      given_name: "Race",
      family_name: "Condition",
      emailVerified: true,
    },
    continuation: null,
    expiresAt: new Date(Date.now() + 60_000),
    consumedAt: null,
  });
  await pending.adapter.create({
    pendingProfileId: "pending_update",
    sourceMethod: "oauth2",
    email: "nikos@example.com",
    missingFields: ["family_name"],
    prefill: {
      given_name: "Nikos",
      emailVerified: true,
    },
    continuation: null,
    expiresAt: new Date(Date.now() + 60_000),
    consumedAt: null,
  });

  const originalConsume = pending.adapter.consume;
  pending.adapter.consume = async (pendingProfileId) => {
    if (pendingProfileId === "pending_race") {
      return false;
    }
    return originalConsume(pendingProfileId);
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      pendingProfiles: pending.adapter,
    },
    plugins: [] as const,
    validateConfigOnStart: true,
  });

  const raced = await auth.completeProfile({
    pendingProfileId: "pending_race",
    profile: {},
  });
  assert.equal(raced.ok, false);
  if (!raced.ok) {
    assert.equal(raced.error.code, "PROFILE_COMPLETION_EXPIRED");
  }
  assert.equal(users.byEmail.get("new@example.com")?.given_name, "Race");

  const updated = await auth.completeProfile({
    pendingProfileId: "pending_update",
    profile: {
      family_name: "Gram",
    },
  });
  assert.equal(updated.ok, true);
  if (!updated.ok) {
    return;
  }

  assert.equal(updated.user.id, "user_existing");
  assert.equal(updated.user.given_name, "Nikos");
  assert.equal(updated.user.family_name, "Gram");
  assert.equal(users.byId.size, 2);
});
