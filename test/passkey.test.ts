import assert from "node:assert/strict";
import { test } from "vite-plus/test";

import { OglofusAuth, passkeyPlugin, type PasskeyAdapter, type UserBase } from "../src/index.js";
import { createSessionStore, createUserStore } from "./helpers/in-memory.js";

interface User extends UserBase {
  given_name: string;
}

const createPasskeyEnv = () => {
  const users = createUserStore<User>();
  const sessions = createSessionStore();
  const credentials = new Map<
    string,
    {
      id: string;
      userId: string;
      credentialId: string;
      publicKey: string;
      counter: number;
      createdAt: Date;
      transports?: string[];
    }
  >();

  const passkeys: PasskeyAdapter = {
    findByCredentialId: async (credentialId) =>
      [...credentials.values()].find((credential) => credential.credentialId === credentialId) ?? null,
    listByUserId: async (userId) => [...credentials.values()].filter((credential) => credential.userId === userId),
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

  return { auth, users, credentials };
};

test("passkey register and authenticate", async () => {
  const { auth } = createPasskeyEnv();

  const register = await auth.register({
    method: "passkey",
    email: "passkey@example.com",
    given_name: "Pass",
    registration: {
      credentialId: "cred-1",
      publicKey: "pub",
      counter: 0,
      transports: ["usb"],
    },
  });

  assert.equal(register.ok, true);

  const login = await auth.authenticate({
    method: "passkey",
    authentication: {
      credentialId: "cred-1",
      nextCounter: 1,
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
    registration: {
      credentialId: "cred-1",
      publicKey: "pub",
      counter: 0,
    },
  });

  await auth.authenticate({
    method: "passkey",
    authentication: {
      credentialId: "cred-1",
      nextCounter: 1,
    },
  });

  const replay = await auth.authenticate({
    method: "passkey",
    authentication: {
      credentialId: "cred-1",
      nextCounter: 1,
    },
  });

  assert.equal(replay.ok, false);
  if (!replay.ok) {
    assert.equal(replay.error.code, "PASSKEY_INVALID_ASSERTION");
  }
});

test("passkey register rejects duplicate credentials", async () => {
  const { auth } = createPasskeyEnv();

  await auth.register({
    method: "passkey",
    email: "passkey@example.com",
    given_name: "Pass",
    registration: {
      credentialId: "cred-1",
      publicKey: "pub",
      counter: 0,
    },
  });

  const duplicate = await auth.register({
    method: "passkey",
    email: "second@example.com",
    given_name: "Second",
    registration: {
      credentialId: "cred-1",
      publicKey: "pub-2",
      counter: 0,
    },
  });

  assert.equal(duplicate.ok, false);
  if (!duplicate.ok) {
    assert.equal(duplicate.error.code, "CONFLICT");
  }
});

test("passkey authenticate requires credentialId and rejects unknown credentials", async () => {
  const { auth } = createPasskeyEnv();

  const missingCredential = await auth.authenticate({
    method: "passkey",
    authentication: {
      credentialId: "",
      nextCounter: 1,
    },
  });

  assert.equal(missingCredential.ok, false);
  if (!missingCredential.ok) {
    assert.equal(missingCredential.error.code, "PASSKEY_INVALID_ASSERTION");
  }

  const unknownCredential = await auth.authenticate({
    method: "passkey",
    authentication: {
      credentialId: "cred-missing",
      nextCounter: 1,
    },
  });

  assert.equal(unknownCredential.ok, false);
  if (!unknownCredential.ok) {
    assert.equal(unknownCredential.error.code, "PASSKEY_INVALID_ASSERTION");
  }
});

test("passkey register requires credentialId and publicKey", async () => {
  const { auth } = createPasskeyEnv();

  const invalid = await auth.register({
    method: "passkey",
    email: "passkey@example.com",
    given_name: "Pass",
    registration: {
      credentialId: "cred-1",
      publicKey: "",
      counter: 0,
    },
  });

  assert.equal(invalid.ok, false);
  if (!invalid.ok) {
    assert.equal(invalid.error.code, "PASSKEY_INVALID_ATTESTATION");
  }
});

test("passkey authenticate returns USER_NOT_FOUND when credential owner no longer exists", async () => {
  const { auth, users } = createPasskeyEnv();

  const register = await auth.register({
    method: "passkey",
    email: "passkey@example.com",
    given_name: "Pass",
    registration: {
      credentialId: "cred-1",
      publicKey: "pub",
      counter: 0,
    },
  });
  assert.equal(register.ok, true);
  if (!register.ok) {
    return;
  }

  users.byId.delete(register.user.id);
  users.byEmail.delete(register.user.email);

  const authResult = await auth.authenticate({
    method: "passkey",
    authentication: {
      credentialId: "cred-1",
      nextCounter: 1,
    },
  });

  assert.equal(authResult.ok, false);
  if (!authResult.ok) {
    assert.equal(authResult.error.code, "USER_NOT_FOUND");
  }
});
