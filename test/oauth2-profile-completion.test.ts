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
  createPendingProfileStore,
  createSessionStore,
  createUserStore,
} from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
  family_name: string;
}

test("oauth2 missing fields returns PROFILE_COMPLETION_REQUIRED and completeProfile finishes auth", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const pending = createPendingProfileStore<User>();

  const linkedAccounts = new Map<string, string>();
  const accounts: OAuth2AccountAdapter<"google"> = {
    findUserId: async (provider, providerUserId) =>
      linkedAccounts.get(`${provider}:${providerUserId}`) ?? null,
    linkAccount: async (input) => {
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
            client: {
              validateAuthorizationCode: async () =>
                new OAuth2Tokens({
                  access_token: "access-token",
                  refresh_token: "refresh-token",
                  token_type: "bearer",
                }),
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
});
