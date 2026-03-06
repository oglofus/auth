import test from "node:test";
import assert from "node:assert/strict";

import { OglofusAuth, passwordPlugin, type PasswordCredentialAdapter, type UserBase } from "../src/index.js";
import {
  createIdentityStore,
  createRateLimiterStore,
  createSessionStore,
  createUserStore,
} from "./helpers/in-memory.js";

interface User extends UserBase {}

const credentials: PasswordCredentialAdapter = {
  getPasswordHash: async () => null,
  setPasswordHash: async () => {},
};

const createAuth = (mode: "private" | "explicit") => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const identity = createIdentityStore();

  const auth = new OglofusAuth({
    accountDiscovery: { mode },
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      identity: identity.adapter,
    },
    plugins: [
      passwordPlugin<User, never>({
        requiredProfileFields: [] as const,
        credentials,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  return { auth, identity };
};

test("discover private mode always returns generic action", async () => {
  const { auth, identity } = createAuth("private");
  identity.byEmail.set("existing@example.com", {
    userId: "u1",
    methods: [{ method: "password" }],
  });

  const res = await auth.discover({
    intent: "login",
    email: "existing@example.com",
  });

  assert.equal(res.ok, true);
  if (!res.ok) {
    return;
  }

  assert.equal(res.data.action, "continue_generic");
  assert.equal(res.data.reason, "DISCOVERY_PRIVATE");
});

test("discover explicit mode routes based on account existence", async () => {
  const { auth, identity } = createAuth("explicit");
  identity.byEmail.set("existing@example.com", {
    userId: "u1",
    methods: [{ method: "oauth2", provider: "google" }, { method: "email_otp" }],
  });

  const login = await auth.discover({ intent: "login", email: "existing@example.com" });
  assert.equal(login.ok, true);
  if (login.ok) {
    assert.equal(login.data.action, "continue_login");
    assert.equal(login.data.reason, "ACCOUNT_FOUND");
    assert.equal(login.data.suggestedMethods.length, 2);
  }

  const register = await auth.discover({ intent: "register", email: "existing@example.com" });
  assert.equal(register.ok, true);
  if (register.ok) {
    assert.equal(register.data.action, "redirect_login");
    assert.equal(register.data.reason, "ACCOUNT_EXISTS");
  }

  const missing = await auth.discover({ intent: "login", email: "missing@example.com" });
  assert.equal(missing.ok, true);
  if (missing.ok) {
    assert.equal(missing.data.action, "redirect_register");
    assert.equal(missing.data.reason, "ACCOUNT_NOT_FOUND");
  }
});

test("explicit discovery mode requires identity adapter", () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();

  assert.throws(() => {
    new OglofusAuth({
      accountDiscovery: { mode: "explicit" },
      adapters: {
        users: users.adapter,
        sessions: sessions.adapter,
      },
      plugins: [
        passwordPlugin<User, never>({
          requiredProfileFields: [] as const,
          credentials,
        }),
      ] as const,
      validateConfigOnStart: true,
    });
  });
});

test("discover is rate limited when rateLimiter is configured", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const identity = createIdentityStore();
  const rateLimiter = createRateLimiterStore();

  const auth = new OglofusAuth({
    accountDiscovery: { mode: "private" },
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      identity: identity.adapter,
      rateLimiter: rateLimiter.adapter,
    },
    plugins: [
      passwordPlugin<User, never>({
        requiredProfileFields: [] as const,
        credentials,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const result = await auth.discover(
      { intent: "login", email: "existing@example.com" },
      { ip: "203.0.113.10" },
    );
    assert.equal(result.ok, true);
  }

  const blocked = await auth.discover(
    { intent: "login", email: "existing@example.com" },
    { ip: "203.0.113.10" },
  );

  assert.equal(blocked.ok, false);
  if (!blocked.ok) {
    assert.equal(blocked.error.code, "RATE_LIMITED");
    assert.equal(blocked.error.meta?.retryAfterSeconds, 60);
  }
});
