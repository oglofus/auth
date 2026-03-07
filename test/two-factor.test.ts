import assert from "node:assert/strict";
import test from "node:test";

import {
  OglofusAuth,
  passwordPlugin,
  testHelpers,
  twoFactorPlugin,
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

const decodeOtpauthSecret = (value: string): string => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";

  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) {
      throw new Error(`Invalid base32 character: ${char}`);
    }
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }

  return Buffer.from(bytes).toString("base64url");
};

const createTwoFactorEnv = (options?: { requiredMethods?: readonly ("totp" | "recovery_code")[] }) => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const passwordHashes = new Map<string, string>();
  const pendingChallenges = new Map<
    string,
    Awaited<ReturnType<TwoFactorChallengeAdapter["findById"]>> extends infer T ? Exclude<T, null> : never
  >();
  const totpSecrets = new Map<
    string,
    { id: string; userId: string; encryptedSecret: string; createdAt: Date; disabledAt?: Date | null }
  >();
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
        requiredMethods: (options?.requiredMethods ?? ["totp"]) as readonly ("totp" | "recovery_code")[],
        challenges,
        totp,
        recoveryCodes: recovery,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  return { auth, totpSecrets, pendingChallenges, recoveryCodes };
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

test("two-factor verification rejects expired and consumed challenges", async () => {
  const { auth, totpSecrets, pendingChallenges } = createTwoFactorEnv();

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

  const pendingAuthId = String(step1.error.meta?.pendingAuthId ?? "");
  const pending = pendingChallenges.get(pendingAuthId);
  if (pending) {
    pendingChallenges.set(pendingAuthId, {
      ...pending,
      expiresAt: new Date(Date.now() - 1_000),
    });
  }

  const expired = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId,
    code: testHelpers.generateTotp(secret, new Date()),
  });
  assert.equal(expired.ok, false);
  if (!expired.ok) {
    assert.equal(expired.error.code, "TWO_FACTOR_EXPIRED");
  }

  const again = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
  });
  assert.equal(again.ok, false);
  if (again.ok) {
    return;
  }

  const nextPendingId = String(again.error.meta?.pendingAuthId ?? "");
  const validCode = testHelpers.generateTotp(secret, new Date());
  const first = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: nextPendingId,
    code: validCode,
  });
  assert.equal(first.ok, true);

  const replay = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: nextPendingId,
    code: validCode,
  });
  assert.equal(replay.ok, false);
  if (!replay.ok) {
    assert.equal(replay.error.code, "TWO_FACTOR_INVALID");
  }
});

test("two-factor supports recovery codes and enrollment APIs", async () => {
  const { auth, totpSecrets, recoveryCodes } = createTwoFactorEnv({
    requiredMethods: ["totp", "recovery_code"] as const,
  });

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

  const twoFactor = auth.method("two_factor");
  const enrollment = await twoFactor.beginTotpEnrollment(register.user.id);
  assert.equal(enrollment.ok, true);
  if (!enrollment.ok) {
    return;
  }
  assert.match(enrollment.data.otpauthUri, /otpauth:\/\//);

  const confirmBad = await twoFactor.confirmTotpEnrollment({
    enrollmentId: enrollment.data.enrollmentId,
    code: "000000",
  });
  assert.equal(confirmBad.ok, false);

  const enrollmentState = await twoFactor.beginTotpEnrollment(register.user.id);
  assert.equal(enrollmentState.ok, true);
  if (!enrollmentState.ok) {
    return;
  }
  const pendingEnrollment = enrollmentState.data.enrollmentId;
  // Enrollment secret is internal, so use the URI from the response to recover it.
  const secret = new URL(enrollmentState.data.otpauthUri).searchParams.get("secret");
  assert.equal(typeof secret, "string");
  const confirm = await twoFactor.confirmTotpEnrollment({
    enrollmentId: pendingEnrollment,
    code: testHelpers.generateTotp(decodeOtpauthSecret(secret!), new Date()),
  });
  assert.equal(confirm.ok, true);
  const storedSecret = totpSecrets.get(register.user.id)?.encryptedSecret;
  assert.equal(typeof storedSecret, "string");

  const regenerated = await twoFactor.regenerateRecoveryCodes(register.user.id);
  assert.equal(regenerated.ok, true);
  if (!regenerated.ok) {
    return;
  }
  assert.equal(regenerated.data.codes.length, 10);
  assert.equal((recoveryCodes.get(register.user.id) ?? []).length, 10);

  const step1 = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
  });
  assert.equal(step1.ok, false);
  if (step1.ok) {
    return;
  }

  const recovery = regenerated.data.codes[0]!;
  const step2 = await auth.verifySecondFactor({
    method: "recovery_code",
    pendingAuthId: String(step1.error.meta?.pendingAuthId ?? ""),
    code: recovery,
  });
  assert.equal(step2.ok, true);

  const totpStep1 = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
  });
  assert.equal(totpStep1.ok, false);
  if (totpStep1.ok || typeof storedSecret !== "string") {
    return;
  }

  const totpStep2 = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: String(totpStep1.error.meta?.pendingAuthId ?? ""),
    code: testHelpers.generateTotp(storedSecret, new Date()),
  });
  assert.equal(totpStep2.ok, true);

  const retry = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
  });
  assert.equal(retry.ok, false);
  if (retry.ok) {
    return;
  }
  const invalidRecovery = await auth.verifySecondFactor({
    method: "recovery_code",
    pendingAuthId: String(retry.error.meta?.pendingAuthId ?? ""),
    code: recovery,
  });
  assert.equal(invalidRecovery.ok, false);
  if (!invalidRecovery.ok) {
    assert.equal(invalidRecovery.error.code, "RECOVERY_CODE_INVALID");
  }
});

test("two-factor returns plugin misconfigured when required adapters are missing", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const passwordHashes = new Map<string, string>();
  const pendingChallenges = new Map<
    string,
    Awaited<ReturnType<TwoFactorChallengeAdapter["findById"]>> extends infer T ? Exclude<T, null> : never
  >();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      passwordPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        credentials: {
          getPasswordHash: async (userId) => passwordHashes.get(userId) ?? null,
          setPasswordHash: async (userId, passwordHash) => {
            passwordHashes.set(userId, passwordHash);
          },
        },
      }),
      twoFactorPlugin<User>({
        requiredMethods: ["totp", "recovery_code"] as const,
        challenges: {
          create: async (challenge) => {
            pendingChallenges.set(challenge.id, challenge);
          },
          findById: async (id) => pendingChallenges.get(id) ?? null,
          consume: async (id) => {
            const found = pendingChallenges.get(id);
            if (!found || found.consumedAt) {
              return false;
            }
            pendingChallenges.set(id, { ...found, consumedAt: new Date() });
            return true;
          },
        },
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const registered = await auth.register({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
    given_name: "Nikos",
  });
  assert.equal(registered.ok, true);
  if (!registered.ok) {
    return;
  }

  const enrollment = await auth.method("two_factor").beginTotpEnrollment(registered.user.id);
  assert.equal(enrollment.ok, false);
  if (!enrollment.ok) {
    assert.equal(enrollment.error.code, "PLUGIN_MISCONFIGURED");
  }

  const regen = await auth.method("two_factor").regenerateRecoveryCodes(registered.user.id);
  assert.equal(regen.ok, false);
  if (!regen.ok) {
    assert.equal(regen.error.code, "PLUGIN_MISCONFIGURED");
  }

  const gated = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "secret",
  });
  assert.equal(gated.ok, false);
  if (gated.ok) {
    return;
  }

  const verifyTotp = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: String(gated.error.meta?.pendingAuthId ?? ""),
    code: "000000",
  });
  assert.equal(verifyTotp.ok, false);
  if (!verifyTotp.ok) {
    assert.equal(verifyTotp.error.code, "PLUGIN_MISCONFIGURED");
  }
});
