import assert from "node:assert/strict";
import test from "node:test";

import {
  OglofusAuth,
  magicLinkPlugin,
  type MagicLinkAdapter,
  type MagicLinkDeliveryHandler,
  type UserBase,
} from "../src/index.js";
import { createOutboxStore, createRateLimiterStore, createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

const createMagicLinkEnv = (options?: { outbox?: ReturnType<typeof createOutboxStore>["adapter"]; deliveryAccepted?: boolean }) => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const tokens = new Map<string, Awaited<ReturnType<MagicLinkAdapter["createToken"]>>>();
  const sentLinks: string[] = [];

  const links: MagicLinkAdapter = {
    createToken: async (input) => {
      const token = {
        id: crypto.randomUUID(),
        userId: input.userId,
        email: input.email,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        consumedAt: null,
      };
      tokens.set(token.id, token);
      return token;
    },
    findActiveTokenByHash: async (tokenHash) =>
      [...tokens.values()].find((token) => token.tokenHash === tokenHash && token.consumedAt === null) ?? null,
    consumeToken: async (tokenId) => {
      const found = tokens.get(tokenId);
      if (!found || found.consumedAt !== null) {
        return false;
      }
      tokens.set(tokenId, {
        ...found,
        consumedAt: new Date(),
      });
      return true;
    },
  };

  const delivery: MagicLinkDeliveryHandler = {
    send: async (payload) => {
      sentLinks.push(payload.link);
      return {
        accepted: options?.deliveryAccepted ?? true,
      };
    },
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      ...(options?.outbox ? { outbox: options.outbox } : {}),
    },
    plugins: [
      magicLinkPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        links,
        delivery,
        baseVerifyUrl: "https://example.com/magic",
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  return { auth, users, sentLinks, tokens };
};

test("magic link authenticate existing account", async () => {
  const { auth, users, sentLinks } = createMagicLinkEnv();

  await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const api = auth.method("magic_link");
  const request = await api.request({ email: "existing@example.com" });
  assert.equal(request.ok, true);
  assert.equal(sentLinks.length, 1);

  const link = new URL(sentLinks[0]);
  const token = link.searchParams.get("token");

  const login = await auth.authenticate({ method: "magic_link", token: token! });
  assert.equal(login.ok, true);
  if (login.ok) {
    assert.equal(login.user.email, "existing@example.com");
  }
});

test("magic link register new account", async () => {
  const { auth, sentLinks } = createMagicLinkEnv();

  const api = auth.method("magic_link");
  const request = await api.request({ email: "new@example.com" });
  assert.equal(request.ok, true);
  assert.equal(sentLinks.length, 1);

  const link = new URL(sentLinks[0]);
  const token = link.searchParams.get("token");

  const register = await auth.register({
    method: "magic_link",
    token: token!,
    given_name: "New",
  });

  assert.equal(register.ok, true);
  if (register.ok) {
    assert.equal(register.user.email, "new@example.com");
  }
});

test("magic link request is rate limited when rateLimiter is configured", async () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const rateLimiter = createRateLimiterStore();
  const tokens = new Map<string, Awaited<ReturnType<MagicLinkAdapter["createToken"]>>>();

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
      rateLimiter: rateLimiter.adapter,
    },
    plugins: [
      magicLinkPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        links: {
          createToken: async (input) => {
            const token = {
              id: crypto.randomUUID(),
              userId: input.userId,
              email: input.email,
              tokenHash: input.tokenHash,
              expiresAt: input.expiresAt,
              consumedAt: null,
            };
            tokens.set(token.id, token);
            return token;
          },
          findActiveTokenByHash: async (tokenHash) =>
            [...tokens.values()].find((token) => token.tokenHash === tokenHash && token.consumedAt === null) ?? null,
          consumeToken: async (tokenId) => {
            const found = tokens.get(tokenId);
            if (!found || found.consumedAt !== null) {
              return false;
            }
            tokens.set(tokenId, {
              ...found,
              consumedAt: new Date(),
            });
            return true;
          },
        },
        delivery: {
          send: async () => ({ accepted: true }),
        },
        baseVerifyUrl: "https://example.com/magic",
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  const api = auth.method("magic_link");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await api.request({ email: "new@example.com" }, { ip: "203.0.113.15" });
    assert.equal(result.ok, true);
  }

  const blocked = await api.request({ email: "new@example.com" }, { ip: "203.0.113.15" });

  assert.equal(blocked.ok, false);
  if (!blocked.ok) {
    assert.equal(blocked.error.code, "RATE_LIMITED");
    assert.equal(blocked.error.meta?.retryAfterSeconds, 300);
  }
});

test("magic link rejects expired and reused tokens", async () => {
  const { auth, users, sentLinks, tokens } = createMagicLinkEnv();

  await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const requested = await auth.method("magic_link").request({ email: "existing@example.com" });
  assert.equal(requested.ok, true);
  if (!requested.ok) {
    return;
  }

  const expiredLink = new URL(sentLinks[0]);
  const expiredToken = expiredLink.searchParams.get("token")!;
  const stored = tokens.get(requested.data.tokenId);
  if (stored) {
    tokens.set(stored.id, { ...stored, expiresAt: new Date(Date.now() - 1_000) });
  }

  const expired = await auth.authenticate({ method: "magic_link", token: expiredToken });
  assert.equal(expired.ok, false);
  if (!expired.ok) {
    assert.equal(expired.error.code, "MAGIC_LINK_EXPIRED");
  }

  const freshRequest = await auth.method("magic_link").request({ email: "existing@example.com" });
  assert.equal(freshRequest.ok, true);
  if (!freshRequest.ok) {
    return;
  }
  const freshToken = new URL(sentLinks[sentLinks.length - 1]).searchParams.get("token")!;

  const first = await auth.authenticate({ method: "magic_link", token: freshToken });
  assert.equal(first.ok, true);

  const replay = await auth.authenticate({ method: "magic_link", token: freshToken });
  assert.equal(replay.ok, false);
  if (!replay.ok) {
    assert.equal(replay.error.code, "MAGIC_LINK_INVALID");
  }
});

test("magic link queues delivery when provider rejects send", async () => {
  const outbox = createOutboxStore();
  const { auth } = createMagicLinkEnv({ outbox: outbox.adapter, deliveryAccepted: false });

  const requested = await auth.method("magic_link").request({ email: "queued@example.com" });
  assert.equal(requested.ok, true);
  if (requested.ok) {
    assert.equal(requested.data.disposition, "queued");
  }
  assert.equal(outbox.messages.length, 1);
  assert.equal(outbox.messages[0]?.payload.kind, "magic_link");
});

test("magic link register rejects existing account and authenticate reports missing user", async () => {
  const { auth, users, sentLinks, tokens } = createMagicLinkEnv();

  const existing = await users.adapter.create({
    email: "existing@example.com",
    emailVerified: true,
    given_name: "Existing",
  } as Omit<User, "id" | "createdAt" | "updatedAt">);

  const registerRequest = await auth.method("magic_link").request({ email: "existing@example.com" });
  assert.equal(registerRequest.ok, true);
  if (!registerRequest.ok) {
    return;
  }
  const registerToken = new URL(sentLinks[0]).searchParams.get("token")!;

  const register = await auth.register({
    method: "magic_link",
    token: registerToken,
    given_name: "Other",
  });
  assert.equal(register.ok, false);
  if (!register.ok) {
    assert.equal(register.error.code, "ACCOUNT_EXISTS");
  }

  const loginRequest = await auth.method("magic_link").request({ email: "existing@example.com" });
  assert.equal(loginRequest.ok, true);
  if (!loginRequest.ok) {
    return;
  }
  const loginToken = new URL(sentLinks[sentLinks.length - 1]).searchParams.get("token")!;
  const tokenRecord = tokens.get(loginRequest.data.tokenId);
  if (tokenRecord) {
    tokens.set(tokenRecord.id, { ...tokenRecord, userId: existing.id });
  }
  users.byId.delete(existing.id);
  users.byEmail.delete(existing.email);

  const login = await auth.authenticate({ method: "magic_link", token: loginToken });
  assert.equal(login.ok, false);
  if (!login.ok) {
    assert.equal(login.error.code, "USER_NOT_FOUND");
  }
});
