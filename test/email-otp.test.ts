import assert from "node:assert/strict";
import test from "node:test";

import {
  OglofusAuth,
  emailOtpPlugin,
  type EmailOtpAdapter,
  type OtpDeliveryHandler,
  type UserBase,
} from "../src/index.js";
import { createOutboxStore, createRateLimiterStore, createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

type Challenge = Awaited<ReturnType<EmailOtpAdapter["createChallenge"]>>;

const createOtpEnv = (options?: {
  rateLimiter?: ReturnType<typeof createRateLimiterStore>["adapter"];
  outbox?: ReturnType<typeof createOutboxStore>["adapter"];
  deliveryAccepted?: boolean;
  security?: {
    rateLimits?: Partial<
      Record<"authenticate" | "emailOtpRequest" | "otpVerify", { limit: number; windowSeconds: number }>
    >;
  };
}) => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const challenges = new Map<string, Challenge>();
  const sentCodes = new Map<string, string>();

  const otp: EmailOtpAdapter = {
    createChallenge: async (input) => {
      const challenge: Challenge = {
        id: crypto.randomUUID(),
        userId: input.userId,
        email: input.email,
        codeHash: input.codeHash,
        expiresAt: input.expiresAt,
        consumedAt: null,
        attempts: 0,
      };
      challenges.set(challenge.id, challenge);
      return challenge;
    },
    findChallengeById: async (challengeId) => challenges.get(challengeId) ?? null,
    consumeChallenge: async (challengeId) => {
      const found = challenges.get(challengeId);
      if (!found || found.consumedAt !== null) {
        return false;
      }
      challenges.set(challengeId, {
        ...found,
        consumedAt: new Date(),
      });
      return true;
    },
    incrementAttempts: async (challengeId) => {
      const found = challenges.get(challengeId);
      if (!found) {
        throw new Error("missing challenge");
      }
      const next = {
        ...found,
        attempts: found.attempts + 1,
      };
      challenges.set(challengeId, next);
      return { attempts: next.attempts };
    },
  };

  const delivery: OtpDeliveryHandler = {
    send: async (payload) => {
      sentCodes.set(payload.email, payload.code);
      return {
        accepted: options?.deliveryAccepted ?? true,
        queuedAt: new Date(),
      };
    },
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      ...(options?.rateLimiter ? { rateLimiter: options.rateLimiter } : {}),
      ...(options?.outbox ? { outbox: options.outbox } : {}),
    },
    security: options?.security,
    plugins: [
      emailOtpPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        otp,
        delivery,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  return { auth, users, sentCodes, challenges };
};

test("email otp request + register flow", async () => {
  const { auth, users, sentCodes } = createOtpEnv();

  const otpApi = auth.method("email_otp");
  const requested = await otpApi.request({ email: "new@example.com" });
  assert.equal(requested.ok, true);
  if (!requested.ok) {
    return;
  }

  const code = sentCodes.get("new@example.com");
  assert.equal(typeof code, "string");

  const register = await auth.register({
    method: "email_otp",
    challengeId: requested.data.challengeId,
    code: code!,
    given_name: "Nikos",
  });

  assert.equal(register.ok, true);
  if (!register.ok) {
    return;
  }

  assert.equal(register.user.email, "new@example.com");
  assert.equal(register.user.emailVerified, true);

  const persisted = await users.adapter.findByEmail("new@example.com");
  assert.equal(persisted?.given_name, "Nikos");
});

test("email otp request + authenticate flow", async () => {
  const { auth, users, sentCodes } = createOtpEnv();

  await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const otpApi = auth.method("email_otp");
  const requested = await otpApi.request({ email: "existing@example.com" });
  assert.equal(requested.ok, true);
  if (!requested.ok) {
    return;
  }

  const login = await auth.authenticate({
    method: "email_otp",
    challengeId: requested.data.challengeId,
    code: sentCodes.get("existing@example.com")!,
  });

  assert.equal(login.ok, true);
  if (!login.ok) {
    return;
  }

  assert.equal(login.user.email, "existing@example.com");
});

test("email otp authenticate rejects invalid code", async () => {
  const { auth, users } = createOtpEnv();

  await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const otpApi = auth.method("email_otp");
  const requested = await otpApi.request({ email: "existing@example.com" });
  assert.equal(requested.ok, true);
  if (!requested.ok) {
    return;
  }

  const login = await auth.authenticate({
    method: "email_otp",
    challengeId: requested.data.challengeId,
    code: "000000",
  });

  assert.equal(login.ok, false);
  if (login.ok) {
    return;
  }

  assert.equal(login.error.code, "OTP_INVALID");
});

test("email otp request is rate limited when rateLimiter is configured", async () => {
  const rateLimiter = createRateLimiterStore();
  const { auth } = createOtpEnv({ rateLimiter: rateLimiter.adapter });

  const otpApi = auth.method("email_otp");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await otpApi.request({ email: "new@example.com" }, { ip: "203.0.113.13" });
    assert.equal(result.ok, true);
  }

  const blocked = await otpApi.request({ email: "new@example.com" }, { ip: "203.0.113.13" });

  assert.equal(blocked.ok, false);
  if (!blocked.ok) {
    assert.equal(blocked.error.code, "RATE_LIMITED");
    assert.equal(blocked.error.meta?.retryAfterSeconds, 300);
  }
});

test("email otp verification is rate limited separately from the global authenticate limiter", async () => {
  const rateLimiter = createRateLimiterStore();
  const { auth, users } = createOtpEnv({
    rateLimiter: rateLimiter.adapter,
    security: {
      rateLimits: {
        authenticate: { limit: 50, windowSeconds: 300 },
        otpVerify: { limit: 2, windowSeconds: 300 },
      },
    },
  });

  await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const otpApi = auth.method("email_otp");
  const requested = await otpApi.request({ email: "existing@example.com" });
  assert.equal(requested.ok, true);
  if (!requested.ok) {
    return;
  }

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const login = await auth.authenticate(
      {
        method: "email_otp",
        challengeId: requested.data.challengeId,
        code: "000000",
      },
      { ip: "203.0.113.14" },
    );
    assert.equal(login.ok, false);
    if (!login.ok) {
      assert.equal(login.error.code, "OTP_INVALID");
    }
  }

  const blocked = await auth.authenticate(
    {
      method: "email_otp",
      challengeId: requested.data.challengeId,
      code: "000000",
    },
    { ip: "203.0.113.14" },
  );

  assert.equal(blocked.ok, false);
  if (!blocked.ok) {
    assert.equal(blocked.error.code, "RATE_LIMITED");
    assert.equal(blocked.error.meta?.retryAfterSeconds, 300);
  }
});

test("email otp rejects expired and reused challenges", async () => {
  const { auth, users, sentCodes, challenges } = createOtpEnv();

  await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const otpApi = auth.method("email_otp");
  const expiredRequest = await otpApi.request({ email: "existing@example.com" });
  assert.equal(expiredRequest.ok, true);
  if (!expiredRequest.ok) {
    return;
  }

  const expired = challenges.get(expiredRequest.data.challengeId);
  if (expired) {
    challenges.set(expired.id, { ...expired, expiresAt: new Date(Date.now() - 1_000) });
  }

  const expiredAttempt = await auth.authenticate({
    method: "email_otp",
    challengeId: expiredRequest.data.challengeId,
    code: sentCodes.get("existing@example.com")!,
  });
  assert.equal(expiredAttempt.ok, false);
  if (!expiredAttempt.ok) {
    assert.equal(expiredAttempt.error.code, "OTP_EXPIRED");
  }

  const freshRequest = await otpApi.request({ email: "existing@example.com" });
  assert.equal(freshRequest.ok, true);
  if (!freshRequest.ok) {
    return;
  }

  const firstLogin = await auth.authenticate({
    method: "email_otp",
    challengeId: freshRequest.data.challengeId,
    code: sentCodes.get("existing@example.com")!,
  });
  assert.equal(firstLogin.ok, true);

  const replay = await auth.authenticate({
    method: "email_otp",
    challengeId: freshRequest.data.challengeId,
    code: sentCodes.get("existing@example.com")!,
  });
  assert.equal(replay.ok, false);
  if (!replay.ok) {
    assert.equal(replay.error.code, "OTP_INVALID");
  }
});

test("email otp enforces max attempt lockout", async () => {
  const { auth, users } = createOtpEnv();

  await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const requested = await auth.method("email_otp").request({ email: "existing@example.com" });
  assert.equal(requested.ok, true);
  if (!requested.ok) {
    return;
  }

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const result = await auth.authenticate({
      method: "email_otp",
      challengeId: requested.data.challengeId,
      code: "000000",
    });
    assert.equal(result.ok, false);
  }

  const blocked = await auth.authenticate({
    method: "email_otp",
    challengeId: requested.data.challengeId,
    code: "000000",
  });
  assert.equal(blocked.ok, false);
  if (!blocked.ok) {
    assert.equal(blocked.error.code, "RATE_LIMITED");
  }
});

test("email otp queues delivery through outbox when provider rejects send", async () => {
  const outbox = createOutboxStore();
  const { auth } = createOtpEnv({
    outbox: outbox.adapter,
    deliveryAccepted: false,
  });

  const requested = await auth.method("email_otp").request({ email: "new@example.com" });
  assert.equal(requested.ok, true);
  if (requested.ok) {
    assert.equal(requested.data.disposition, "queued");
  }
  assert.equal(outbox.messages.length, 1);
  assert.equal(outbox.messages[0]?.payload.kind, "email_otp");
});

test("email otp register rejects existing account and authenticate reports missing user", async () => {
  const { auth, users, sentCodes, challenges } = createOtpEnv();

  const existing = await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const requested = await auth.method("email_otp").request({ email: "existing@example.com" });
  assert.equal(requested.ok, true);
  if (!requested.ok) {
    return;
  }

  const register = await auth.register({
    method: "email_otp",
    challengeId: requested.data.challengeId,
    code: sentCodes.get("existing@example.com")!,
    given_name: "Other",
  });
  assert.equal(register.ok, false);
  if (!register.ok) {
    assert.equal(register.error.code, "ACCOUNT_EXISTS");
  }

  const missingUserRequest = await auth.method("email_otp").request({ email: "existing@example.com" });
  assert.equal(missingUserRequest.ok, true);
  if (!missingUserRequest.ok) {
    return;
  }

  users.byId.delete(existing.id);
  users.byEmail.delete(existing.email);
  const challenge = challenges.get(missingUserRequest.data.challengeId);
  if (challenge) {
    challenges.set(challenge.id, { ...challenge, userId: existing.id });
  }

  const login = await auth.authenticate({
    method: "email_otp",
    challengeId: missingUserRequest.data.challengeId,
    code: sentCodes.get("existing@example.com")!,
  });
  assert.equal(login.ok, false);
  if (!login.ok) {
    assert.equal(login.error.code, "USER_NOT_FOUND");
  }
});
