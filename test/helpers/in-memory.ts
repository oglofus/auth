import type {
  AuditAdapter,
  AuditRecord,
  IdentityAdapter,
  IdempotencyAdapter,
  OrganizationSessionAdapter,
  PendingProfileAdapter,
  PendingProfileRecord,
  RateLimiterAdapter,
  SessionAdapter,
  UserAdapter,
} from "../../src/types/adapters.js";
import type { Session, SignInMethodHint, UserBase } from "../../src/types/model.js";

export type TestUser = UserBase & {
  given_name?: string;
  family_name?: string;
  [key: string]: unknown;
};

export const createUserStore = <U extends UserBase>(seed: U[] = []) => {
  const byId = new Map<string, U>();
  const byEmail = new Map<string, U>();

  for (const user of seed) {
    byId.set(user.id, user);
    byEmail.set(user.email, user);
  }

  const adapter: UserAdapter<U> = {
    findById: async (id) => byId.get(id) ?? null,
    findByEmail: async (email) => byEmail.get(email) ?? null,
    create: async (input) => {
      const user = {
        ...(input as Record<string, unknown>),
        id: crypto.randomUUID(),
        createdAt: new Date(),
        updatedAt: new Date(),
      } as U;

      byId.set(user.id, user);
      byEmail.set(user.email, user);
      return user;
    },
    update: async (id, patch) => {
      const current = byId.get(id);
      if (!current) {
        return null;
      }

      const next = {
        ...current,
        ...patch,
        updatedAt: new Date(),
      } as U;

      byId.set(id, next);
      byEmail.set(next.email, next);
      return next;
    },
  };

  return {
    byId,
    byEmail,
    adapter,
  };
};

export const createSessionStore = () => {
  const byId = new Map<string, Session>();

  const adapter: SessionAdapter = {
    create: async (session) => {
      byId.set(session.id, session);
    },
    findById: async (id) => byId.get(id) ?? null,
    revoke: async (id) => {
      const session = byId.get(id);
      if (!session) {
        return;
      }
      byId.set(id, {
        ...session,
        revokedAt: new Date(),
      });
    },
    revokeAllForUser: async (userId) => {
      for (const [id, session] of byId.entries()) {
        if (session.userId === userId) {
          byId.set(id, {
            ...session,
            revokedAt: new Date(),
          });
        }
      }
    },
  };

  const organizationAdapter: OrganizationSessionAdapter = {
    setActiveOrganization: async (sessionId, organizationId) => {
      const session = byId.get(sessionId);
      if (!session) {
        return null;
      }

      const next = {
        ...session,
        activeOrganizationId: organizationId,
      };
      byId.set(sessionId, next);
      return next;
    },
  };

  return {
    byId,
    adapter,
    organizationAdapter,
  };
};

export const createPendingProfileStore = <U extends UserBase>() => {
  const byId = new Map<string, PendingProfileRecord<U>>();

  const adapter: PendingProfileAdapter<U> = {
    create: async (record) => {
      byId.set(record.pendingProfileId, record);
    },
    findById: async (pendingProfileId) => byId.get(pendingProfileId) ?? null,
    consume: async (pendingProfileId) => {
      const found = byId.get(pendingProfileId);
      if (!found || found.consumedAt !== null || found.expiresAt.getTime() <= Date.now()) {
        return false;
      }

      byId.set(pendingProfileId, {
        ...found,
        consumedAt: new Date(),
      });
      return true;
    },
  };

  return {
    byId,
    adapter,
  };
};

export const createIdentityStore = () => {
  const byEmail = new Map<string, { userId: string; methods: SignInMethodHint[] }>();

  const adapter: IdentityAdapter = {
    findByEmail: async (email) => {
      const found = byEmail.get(email);
      if (!found) {
        return null;
      }

      return {
        userId: found.userId,
        email,
        methods: found.methods,
      };
    },
  };

  return {
    byEmail,
    adapter,
  };
};

export const createAuditStore = () => {
  const records: AuditRecord[] = [];

  const adapter: AuditAdapter = {
    write: async (record) => {
      records.push(record);
    },
  };

  return {
    records,
    adapter,
  };
};

export const createRateLimiterStore = () => {
  const counts = new Map<string, number>();

  const adapter: RateLimiterAdapter = {
    consume: async (key, limit, windowSeconds) => {
      const next = (counts.get(key) ?? 0) + 1;
      counts.set(key, next);

      if (next <= limit) {
        return { allowed: true };
      }

      return {
        allowed: false,
        retryAfterSeconds: windowSeconds,
      };
    },
  };

  return {
    counts,
    adapter,
  };
};

export const createIdempotencyStore = () => {
  const seen = new Set<string>();

  const adapter: IdempotencyAdapter = {
    checkAndSet: async (key) => {
      if (seen.has(key)) {
        return false;
      }

      seen.add(key);
      return true;
    },
  };

  return {
    seen,
    adapter,
  };
};
