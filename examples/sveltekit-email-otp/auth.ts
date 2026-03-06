import {
  OglofusAuth,
  emailOtpPlugin,
  type EmailOtpAdapter,
  type OtpDeliveryHandler,
  type Session,
  type SessionAdapter,
  type UserAdapter,
  type UserBase,
} from "@oglofus/auth";

export interface AppUser extends UserBase {
  given_name: string;
}

type Challenge = Awaited<ReturnType<EmailOtpAdapter["createChallenge"]>>;

const usersById = new Map<string, AppUser>();
const usersByEmail = new Map<string, AppUser>();
const sessionsById = new Map<string, Session>();
const challenges = new Map<string, Challenge>();
const lastCodeByEmail = new Map<string, string>();

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
    const challenge = challenges.get(challengeId);
    if (!challenge || challenge.consumedAt) {
      return false;
    }
    challenges.set(challengeId, { ...challenge, consumedAt: new Date() });
    return true;
  },
  incrementAttempts: async (challengeId) => {
    const challenge = challenges.get(challengeId);
    if (!challenge) {
      throw new Error("Missing OTP challenge");
    }
    const next = { ...challenge, attempts: challenge.attempts + 1 };
    challenges.set(challengeId, next);
    return { attempts: next.attempts };
  },
};

const delivery: OtpDeliveryHandler = {
  send: async (payload) => {
    lastCodeByEmail.set(payload.email, payload.code);
    console.info(`[dev] OTP for ${payload.email}: ${payload.code}`);
    return { accepted: true, queuedAt: new Date() };
  },
};

export const auth = new OglofusAuth({
  adapters: { users, sessions },
  plugins: [
    emailOtpPlugin<AppUser, "given_name">({
      requiredProfileFields: ["given_name"] as const,
      otp,
      delivery,
    }),
  ] as const,
  validateConfigOnStart: true,
});
