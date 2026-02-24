import test from "node:test";
import assert from "node:assert/strict";

import {
  OglofusAuth,
  magicLinkPlugin,
  type MagicLinkAdapter,
  type MagicLinkDeliveryHandler,
  type UserBase,
} from "../src/index.js";
import { createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

const createMagicLinkEnv = () => {
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
        accepted: true,
      };
    },
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
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

  return { auth, users, sentLinks };
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
