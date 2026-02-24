import {
  OglofusAuth,
  oauth2Plugin,
  type OAuth2AccountAdapter,
  type PendingProfileAdapter,
  type PendingProfileRecord,
  type Session,
  type SessionAdapter,
  type UserAdapter,
  type UserBase,
} from "@oglofus/auth";
import { Google, generateCodeVerifier, generateState } from "arctic";

export interface AppUser extends UserBase {
  given_name: string;
  family_name: string;
}

const usersById = new Map<string, AppUser>();
const usersByEmail = new Map<string, AppUser>();
const sessionsById = new Map<string, Session>();
const linkedAccounts = new Map<string, string>();
const pendingProfiles = new Map<string, PendingProfileRecord<AppUser>>();

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

const accounts: OAuth2AccountAdapter<"google"> = {
  findUserId: async (provider, providerUserId) =>
    linkedAccounts.get(`${provider}:${providerUserId}`) ?? null,
  linkAccount: async (input) => {
    linkedAccounts.set(`${input.provider}:${input.providerUserId}`, input.userId);
  },
};

const pending: PendingProfileAdapter<AppUser> = {
  create: async (record) => {
    pendingProfiles.set(record.pendingProfileId, record);
  },
  findById: async (pendingProfileId) => pendingProfiles.get(pendingProfileId) ?? null,
  consume: async (pendingProfileId) => {
    const found = pendingProfiles.get(pendingProfileId);
    if (!found || found.consumedAt || found.expiresAt.getTime() <= Date.now()) {
      return false;
    }
    pendingProfiles.set(pendingProfileId, { ...found, consumedAt: new Date() });
    return true;
  },
};

const google = new Google(
  process.env.GOOGLE_CLIENT_ID!,
  process.env.GOOGLE_CLIENT_SECRET!,
  process.env.GOOGLE_REDIRECT_URI!,
);

export const auth = new OglofusAuth({
  adapters: {
    users,
    sessions,
    pendingProfiles: pending,
  },
  plugins: [
    oauth2Plugin<AppUser, "google", "given_name" | "family_name">({
      providers: {
        google: {
          client: google,
          resolveProfile: async ({ tokens }) => {
            const response = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
              headers: {
                Authorization: `Bearer ${tokens.accessToken()}`,
              },
            });

            if (!response.ok) {
              throw new Error(`Google profile request failed: ${response.status}`);
            }

            const profile = (await response.json()) as {
              sub: string;
              email?: string;
              email_verified?: boolean;
              given_name?: string;
              family_name?: string;
            };

            return {
              providerUserId: profile.sub,
              email: profile.email,
              emailVerified: profile.email_verified,
              profile: {
                given_name: profile.given_name ?? "",
                family_name: profile.family_name ?? "",
              },
            };
          },
        },
      },
      accounts,
      requiredProfileFields: ["given_name", "family_name"] as const,
    }),
  ] as const,
  validateConfigOnStart: true,
});

export const createGoogleAuthorization = (): {
  state: string;
  codeVerifier: string;
  url: URL;
} => {
  const state = generateState();
  const codeVerifier = generateCodeVerifier();
  const url = google.createAuthorizationURL(state, codeVerifier, ["openid", "email", "profile"]);
  return { state, codeVerifier, url };
};
