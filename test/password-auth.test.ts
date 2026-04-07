import assert from "node:assert/strict";
import { test } from "vite-plus/test";

import { OglofusAuth, passwordPlugin, type PasswordCredentialAdapter, type UserBase } from "../src/index.js";
import { createRateLimiterStore, createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

const createPasswordEnv = () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const credentialStore = new Map<string, string>();

  const credentials: PasswordCredentialAdapter = {
    getPasswordHash: async (userId) => credentialStore.get(userId) ?? null,
    setPasswordHash: async (userId, passwordHash) => {
      credentialStore.set(userId, passwordHash);
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
    ] as const,
    validateConfigOnStart: true,
  });

  return { auth, users, sessions, credentialStore };
};

test("password register/authenticate happy path", async () => {
  const { auth } = createPasswordEnv();

  const register = await auth.register({
    method: "password",
    email: "Nikos@Example.com",
    password: "super-secret",
    given_name: "Nikos",
  });

  assert.equal(register.ok, true);
  if (!register.ok) {
    return;
  }

  assert.equal(register.user.email, "nikos@example.com");
  assert.ok(register.sessionId.length > 0);

  const login = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "super-secret",
  });

  assert.equal(login.ok, true);
  if (!login.ok) {
    return;
  }

  const validSession = await auth.validateSession(login.sessionId);
  assert.deepEqual(validSession, { ok: true, userId: login.user.id });

  await auth.signOut(login.sessionId);
  const invalidAfterSignout = await auth.validateSession(login.sessionId);
  assert.deepEqual(invalidAfterSignout, { ok: false });
});

test("password register enforces required profile field", async () => {
  const { auth } = createPasswordEnv();

  const register = await auth.register({
    method: "password",
    email: "missing@example.com",
    password: "super-secret",
    // runtime-missing field on purpose
  } as any);

  assert.equal(register.ok, false);
  if (register.ok) {
    return;
  }

  assert.equal(register.error.code, "INVALID_INPUT");
  assert.deepEqual(register.issues, [{ message: "given_name is required", path: ["given_name"] }]);
});

test("password authenticate fails on invalid credentials", async () => {
  const { auth } = createPasswordEnv();

  await auth.register({
    method: "password",
    email: "nikos@example.com",
    password: "super-secret",
    given_name: "Nikos",
  });

  const login = await auth.authenticate({
    method: "password",
    email: "nikos@example.com",
    password: "wrong-password",
  });

  assert.equal(login.ok, false);
  if (login.ok) {
    return;
  }

  assert.equal(login.error.code, "INVALID_CREDENTIALS");
});

test("password register and authenticate are rate limited when rateLimiter is configured", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const rateLimiter = createRateLimiterStore();
  const credentialStore = new Map<string, string>();

  const credentials: PasswordCredentialAdapter = {
    getPasswordHash: async (userId) => credentialStore.get(userId) ?? null,
    setPasswordHash: async (userId, passwordHash) => {
      credentialStore.set(userId, passwordHash);
    },
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      rateLimiter: rateLimiter.adapter,
    },
    plugins: [
      passwordPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        credentials,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const result = await auth.register(
      {
        method: "password",
        email: "blocked@example.com",
        password: "super-secret",
        given_name: "Nikos",
      },
      { ip: "203.0.113.11" },
    );
    assert.equal(attempt === 0 ? result.ok : result.ok === false, true);
  }

  const blockedRegister = await auth.register(
    {
      method: "password",
      email: "blocked@example.com",
      password: "super-secret",
      given_name: "Blocked",
    },
    { ip: "203.0.113.11" },
  );

  assert.equal(blockedRegister.ok, false);
  if (!blockedRegister.ok) {
    assert.equal(blockedRegister.error.code, "RATE_LIMITED");
    assert.equal(blockedRegister.error.meta?.retryAfterSeconds, 300);
  }

  await auth.register({
    method: "password",
    email: "nikos@example.com",
    password: "super-secret",
    given_name: "Nikos",
  });

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const login = await auth.authenticate(
      {
        method: "password",
        email: "nikos@example.com",
        password: "wrong-password",
      },
      { ip: "203.0.113.12" },
    );
    assert.equal(login.ok, false);
  }

  const blockedLogin = await auth.authenticate(
    {
      method: "password",
      email: "nikos@example.com",
      password: "wrong-password",
    },
    { ip: "203.0.113.12" },
  );

  assert.equal(blockedLogin.ok, false);
  if (!blockedLogin.ok) {
    assert.equal(blockedLogin.error.code, "RATE_LIMITED");
    assert.equal(blockedLogin.error.meta?.retryAfterSeconds, 300);
  }
});
