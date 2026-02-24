import {
  OglofusAuth,
  passwordPlugin,
  type PasswordCredentialAdapter,
  type Session,
  type SessionAdapter,
  type UserAdapter,
  type UserBase,
} from "@oglofus/auth";

export interface AppUser extends UserBase {
  given_name: string;
  family_name: string;
}

const usersById = new Map<string, AppUser>();
const usersByEmail = new Map<string, AppUser>();
const sessionsById = new Map<string, Session>();
const passwordHashes = new Map<string, string>();

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
      throw new Error(`Missing user ${id}`);
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
  setActiveOrganization: async (sessionId, organizationId) => {
    const current = sessionsById.get(sessionId);
    if (!current) {
      throw new Error(`Missing session ${sessionId}`);
    }
    const next = { ...current, activeOrganizationId: organizationId };
    sessionsById.set(sessionId, next);
    return next;
  },
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

export const auth = new OglofusAuth({
  adapters: {
    users,
    sessions,
  },
  plugins: [
    passwordPlugin<AppUser, "given_name" | "family_name">({
      requiredProfileFields: ["given_name", "family_name"] as const,
      credentials,
    }),
  ] as const,
  validateConfigOnStart: true,
});
