import test from "node:test";
import assert from "node:assert/strict";

import {
  OglofusAuth,
  passwordPlugin,
  twoFactorPlugin,
  testHelpers,
  type PasswordCredentialAdapter,
  type RecoveryCodeAdapter,
  type TotpAdapter,
  type TwoFactorChallengeAdapter,
  type UserBase,
} from "../src/index.js";
import { createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

const createTwoFactorEnv = () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const passwordHashes = new Map<string, string>();
  const pendingChallenges = new Map<string, Awaited<ReturnType<TwoFactorChallengeAdapter["findById"]>> extends infer T ? Exclude<T, null> : never>();
  const totpSecrets = new Map<string, { id: string; userId: string; encryptedSecret: string; createdAt: Date; disabledAt?: Date | null }>();
  const recoveryCodes = new Map<string, string[]>();

  const credentials: PasswordCredentialAdapter = {
    getPasswordHash: async (userId) => passwordHashes.get(userId) ?? null,
    setPasswordHash: async (userId, passwordHash) => {
      passwordHashes.set(userId, passwordHash);
    },
  };

  const challenges: TwoFactorChallengeAdapter = {
    create: async (challenge) => {
      pendingChallenges.set(challenge.id, challenge);
    },
    findById: async (id) => pendingChallenges.get(id) ?? null,
    consume: async (id) => {
      const found = pendingChallenges.get(id);
      if (!found || found.consumedAt !== null) {
        return false;
      }
      pendingChallenges.set(id, {
        ...found,
        consumedAt: new Date(),
      });
      return true;
    },
  };

  const totp: TotpAdapter = {
    findActiveByUserId: async (userId) => totpSecrets.get(userId) ?? null,
    upsertActive: async (userId, encryptedSecret) => {
      const current = totpSecrets.get(userId);
      totpSecrets.set(userId, {
        id: current?.id ?? crypto.randomUUID(),
        userId,
        encryptedSecret,
        createdAt: current?.createdAt ?? new Date(),
      });
    },
    disable: async (userId) => {
      const current = totpSecrets.get(userId);
      if (!current) {
        return;
      }
      totpSecrets.set(userId, {
        ...current,
        disabledAt: new Date(),
      });
    },
  };

  const recovery: RecoveryCodeAdapter = {
    listActive: async (userId) =>
      (recoveryCodes.get(userId) ?? []).map((codeHash) => ({
        id: crypto.randomUUID(),
        userId,
        codeHash,
        usedAt: null,
      })),
    consume: async (userId, codeHash) => {
      const values = recoveryCodes.get(userId) ?? [];
      const idx = values.indexOf(codeHash);
      if (idx < 0) {
        return false;
      }
      const next = [...values.slice(0, idx), ...values.slice(idx + 1)];
      recoveryCodes.set(userId, next);
      return true;
    },
    replaceAll: async (userId, codeHashes) => {
      recoveryCodes.set(userId, [...codeHashes]);
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
      twoFactorPlugin<User>({
        requiredMethods: ["totp"] as const,
        challenges,
        totp,
        recoveryCodes: recovery,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  return { auth, totpSecrets };
};

test("two-factor plugin gates session issuance until verification", async () => {
  const { auth, totpSecrets } = createTwoFactorEnv();

  const register = await auth.register({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
    given_name: "Nikos",
  });
  assert.equal(register.ok, true);
  if (!register.ok) {
    return;
  }

  const secret = "totp-secret";
  totpSecrets.set(register.user.id, {
    id: crypto.randomUUID(),
    userId: register.user.id,
    encryptedSecret: secret,
    createdAt: new Date(),
  });

  const step1 = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
  });

  assert.equal(step1.ok, false);
  if (step1.ok) {
    return;
  }

  assert.equal(step1.error.code, "TWO_FACTOR_REQUIRED");
  const pendingAuthId = String(step1.error.meta?.pendingAuthId ?? "");
  assert.ok(pendingAuthId.length > 0);

  const code = testHelpers.generateTotp(secret, new Date());
  const step2 = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId,
    code,
  });

  assert.equal(step2.ok, true);
  if (step2.ok) {
    assert.ok(step2.sessionId.length > 0);
  }
});

test("two-factor verification rejects invalid code", async () => {
  const { auth, totpSecrets } = createTwoFactorEnv();

  const register = await auth.register({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
    given_name: "Nikos",
  });
  assert.equal(register.ok, true);
  if (!register.ok) {
    return;
  }

  totpSecrets.set(register.user.id, {
    id: crypto.randomUUID(),
    userId: register.user.id,
    encryptedSecret: "totp-secret",
    createdAt: new Date(),
  });

  const step1 = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
  });

  assert.equal(step1.ok, false);
  if (step1.ok) {
    return;
  }

  const step2 = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: String(step1.error.meta?.pendingAuthId ?? ""),
    code: "000000",
  });

  assert.equal(step2.ok, false);
  if (!step2.ok) {
    assert.equal(step2.error.code, "TWO_FACTOR_INVALID");
  }
});
