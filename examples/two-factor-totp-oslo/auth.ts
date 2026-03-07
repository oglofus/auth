import {
  OglofusAuth,
  passwordPlugin,
  twoFactorPlugin,
  type PasswordCredentialAdapter,
  type RecoveryCodeAdapter,
  type Session,
  type SessionAdapter,
  type TotpAdapter,
  type TwoFactorChallengeAdapter,
  type UserAdapter,
  type UserBase,
} from "@oglofus/auth";

export interface AppUser extends UserBase {
  given_name: string;
}

type PendingChallenge =
  Awaited<ReturnType<TwoFactorChallengeAdapter["findById"]>> extends infer T ? Exclude<T, null | undefined> : never;

const usersById = new Map<string, AppUser>();
const usersByEmail = new Map<string, AppUser>();
const sessionsById = new Map<string, Session>();
const passwordHashes = new Map<string, string>();
const pendingChallenges = new Map<string, PendingChallenge>();
const totpSecrets = new Map<
  string,
  { id: string; userId: string; encryptedSecret: string; createdAt: Date; disabledAt?: Date | null }
>();
const recoveryCodes = new Map<string, string[]>();

const users: UserAdapter<AppUser> = {
  findById: async (id) => usersById.get(id) ?? null,
  findByEmail: async (email) => usersByEmail.get(email) ?? null,
  create: async (input) => {
    const user: AppUser = {
      ...(input as Omit<AppUser, "id" | "createdAt" | "updatedAt">),
      id: crypto.randomUUID(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    usersById.set(user.id, user);
    usersByEmail.set(user.email, user);
    return user;
  },
  update: async (id, patch) => {
    const current = usersById.get(id);
    if (!current) {
      return null;
    }
    const next = { ...current, ...patch, updatedAt: new Date() };
    usersById.set(id, next);
    usersByEmail.set(next.email, next);
    return next;
  },
};

const sessions: SessionAdapter = {
  create: async (session) => {
    sessionsById.set(session.id, session);
  },
  findById: async (id) => sessionsById.get(id) ?? null,
  revoke: async (id) => {
    const current = sessionsById.get(id);
    if (!current) {
      return;
    }
    sessionsById.set(id, { ...current, revokedAt: new Date() });
  },
  revokeAllForUser: async (userId) => {
    for (const [id, session] of sessionsById.entries()) {
      if (session.userId === userId) {
        sessionsById.set(id, { ...session, revokedAt: new Date() });
      }
    }
  },
};

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
    const challenge = pendingChallenges.get(id);
    if (!challenge || challenge.consumedAt) {
      return false;
    }
    pendingChallenges.set(id, { ...challenge, consumedAt: new Date() });
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
      disabledAt: null,
    });
  },
  disable: async (userId) => {
    const current = totpSecrets.get(userId);
    if (!current) {
      return;
    }
    totpSecrets.set(userId, { ...current, disabledAt: new Date() });
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
    const codes = recoveryCodes.get(userId) ?? [];
    const index = codes.indexOf(codeHash);
    if (index < 0) {
      return false;
    }
    recoveryCodes.set(userId, [...codes.slice(0, index), ...codes.slice(index + 1)]);
    return true;
  },
  replaceAll: async (userId, codeHashes) => {
    recoveryCodes.set(userId, [...codeHashes]);
  },
};

export const auth = new OglofusAuth({
  adapters: { users, sessions },
  plugins: [
    passwordPlugin<AppUser, "given_name">({
      requiredProfileFields: ["given_name"] as const,
      credentials,
    }),
    twoFactorPlugin<AppUser>({
      requiredMethods: ["totp"] as const,
      challenges,
      totp,
      recoveryCodes: recovery,
    }),
  ] as const,
  validateConfigOnStart: true,
});
