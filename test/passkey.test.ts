import test from "node:test";
import assert from "node:assert/strict";

import {
  OglofusAuth,
  passkeyPlugin,
  type PasskeyAdapter,
  type UserBase,
} from "../src/index.js";
import { createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

const createPasskeyEnv = () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const credentials = new Map<string, { id: string; userId: string; credentialId: string; publicKey: string; counter: number; createdAt: Date; transports?: string[] }>();

  const passkeys: PasskeyAdapter = {
    findByCredentialId: async (credentialId) =>
      [...credentials.values()].find((credential) => credential.credentialId === credentialId) ?? null,
    listByUserId: async (userId) =>
      [...credentials.values()].filter((credential) => credential.userId === userId),
    create: async (credential) => {
      credentials.set(credential.id, credential);
    },
    updateCounter: async (credentialId, counter) => {
      const current = [...credentials.values()].find((credential) => credential.credentialId === credentialId);
      if (!current) {
        throw new Error("credential not found");
      }
      credentials.set(current.id, {
        ...current,
        counter,
      });
    },
    delete: async (credentialId) => {
      const found = [...credentials.entries()].find(([, credential]) => credential.credentialId === credentialId);
      if (!found) {
        return;
      }
      credentials.delete(found[0]);
    },
  };

  const auth = new OglofusAuth({
    adapters: {
      users: users.adapter,
      sessions: sessions.adapter,
    },
    plugins: [
      passkeyPlugin<User, "given_name">({
        requiredProfileFields: ["given_name"] as const,
        passkeys,
      }),
    ] as const,
    validateConfigOnStart: true,
  });

  return { auth };
};

test("passkey register and authenticate", async () => {
  const { auth } = createPasskeyEnv();

  const register = await auth.register({
    method: "passkey",
    email: "passkey@example.com",
    given_name: "Pass",
    attestation: {
      credentialId: "cred-1",
      publicKey: "pub",
      counter: 0,
    },
  });

  assert.equal(register.ok, true);

  const login = await auth.authenticate({
    method: "passkey",
    assertion: {
      credentialId: "cred-1",
      counter: 1,
    },
  });

  assert.equal(login.ok, true);
  if (login.ok) {
    assert.equal(login.user.email, "passkey@example.com");
  }
});

test("passkey counter regression is rejected", async () => {
  const { auth } = createPasskeyEnv();

  await auth.register({
    method: "passkey",
    email: "passkey@example.com",
    given_name: "Pass",
    attestation: {
      credentialId: "cred-1",
      publicKey: "pub",
      counter: 0,
    },
  });

  await auth.authenticate({
    method: "passkey",
    assertion: {
      credentialId: "cred-1",
      counter: 1,
    },
  });

  const replay = await auth.authenticate({
    method: "passkey",
    assertion: {
      credentialId: "cred-1",
      counter: 1,
    },
  });

  assert.equal(replay.ok, false);
  if (!replay.ok) {
    assert.equal(replay.error.code, "PASSKEY_INVALID_ASSERTION");
  }
});
