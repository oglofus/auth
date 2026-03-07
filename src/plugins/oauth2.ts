import { ArcticFetchError, OAuth2RequestError, type OAuth2Tokens } from "arctic";
import { addSeconds, createId } from "../core/utils.js";
import { ensureFields } from "../core/validators.js";
import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type { OAuth2AccountAdapter } from "../types/adapters.js";
import type { OAuth2AuthenticateInput, UserBase } from "../types/model.js";
import type { AuthMethodPlugin } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";

export type OAuth2ExchangeResult<U extends UserBase, P extends string> = {
  provider: P;
  providerUserId: string;
  email?: string;
  emailVerified?: boolean;
  profile?: Partial<U>;
};

export type ArcticAuthorizationCodeClient =
  | {
      validateAuthorizationCode(code: string, codeVerifier: string): Promise<OAuth2Tokens>;
    }
  | {
      validateAuthorizationCode(code: string, codeVerifier: string | null): Promise<OAuth2Tokens>;
    };

export type OAuth2AuthorizationCodeExchangeInput = {
  authorizationCode: string;
  codeVerifier?: string;
  redirectUri: string;
};

export type OAuth2AuthorizationCodeExchange = (input: OAuth2AuthorizationCodeExchangeInput) => Promise<OAuth2Tokens>;

export type OAuth2ResolvedProfile<U extends UserBase, P extends string> = {
  provider?: P;
  providerUserId: string;
  email?: string;
  emailVerified?: boolean;
  profile?: Partial<U>;
};

export type OAuth2ProviderConfig<U extends UserBase, P extends string> = {
  exchangeAuthorizationCode: OAuth2AuthorizationCodeExchange;
  resolveProfile: (input: {
    provider: P;
    tokens: OAuth2Tokens;
    authenticateInput: OAuth2AuthenticateInput<P>;
  }) => Promise<OAuth2ResolvedProfile<U, P>>;
  pkceRequired?: boolean;
};

export type OAuth2PluginConfig<U extends UserBase, P extends string, K extends keyof U = never> = {
  providers: { [Provider in P]?: OAuth2ProviderConfig<U, Provider> };
  accounts: OAuth2AccountAdapter<P>;
  requiredProfileFields?: readonly K[];
  pendingProfileTtlSeconds?: number;
};

type OAuth2PendingContinuation<P extends string> = {
  provider: P;
  providerUserId: string;
  accessToken?: string;
  refreshToken?: string;
};

export const arcticAuthorizationCodeExchange = (
  client: ArcticAuthorizationCodeClient,
): OAuth2AuthorizationCodeExchange => {
  return async ({ authorizationCode, codeVerifier }) => {
    const validateAuthorizationCode = client.validateAuthorizationCode as (
      code: string,
      verifier: string | null,
    ) => Promise<OAuth2Tokens>;
    return validateAuthorizationCode(authorizationCode, codeVerifier ?? null);
  };
};

const getAccessToken = (tokens: OAuth2Tokens): string | undefined => {
  try {
    return tokens.accessToken();
  } catch {
    return undefined;
  }
};

const getRefreshToken = (tokens: OAuth2Tokens): string | undefined => {
  try {
    return tokens.hasRefreshToken() ? tokens.refreshToken() : undefined;
  } catch {
    return undefined;
  }
};

export const oauth2Plugin = <U extends UserBase, P extends string, K extends keyof U = never>(
  config: OAuth2PluginConfig<U, P, K>,
): AuthMethodPlugin<"oauth2", OAuth2AuthenticateInput<P>, OAuth2AuthenticateInput<P>, U, never, false, false> => {
  const ttl = config.pendingProfileTtlSeconds ?? 10 * 60;
  const requiredProfileFields = (config.requiredProfileFields ?? []) as readonly K[];

  return {
    kind: "auth_method",
    method: "oauth2",
    version: "2.0.0",
    supports: {
      register: false,
    },
    issueFields: {
      authenticate: ["provider", "authorizationCode", "redirectUri", "codeVerifier", "idempotencyKey"],
    },
    completePendingProfile: async (_ctx, { record, user }) => {
      const continuation = record.continuation as OAuth2PendingContinuation<P> | undefined;
      if (
        !continuation ||
        typeof continuation.provider !== "string" ||
        typeof continuation.providerUserId !== "string"
      ) {
        return errorOperation(
          new AuthError(
            "PLUGIN_MISCONFIGURED",
            "Pending OAuth2 profile is missing provider continuation metadata.",
            500,
          ),
        );
      }

      await config.accounts.linkAccount({
        userId: user.id,
        provider: continuation.provider,
        providerUserId: continuation.providerUserId,
        accessToken: continuation.accessToken,
        refreshToken: continuation.refreshToken,
      });

      return successOperation(undefined);
    },
    authenticate: async (ctx, input) => {
      const providerConfig = config.providers[input.provider];
      if (!providerConfig) {
        return errorOperation(
          new AuthError("OAUTH2_PROVIDER_DISABLED", "OAuth2 provider is disabled.", 400, [
            createIssue("Provider disabled", ["provider"]),
          ]),
        );
      }

      if (ctx.adapters.idempotency) {
        if (!input.idempotencyKey || input.idempotencyKey.trim() === "") {
          return errorOperation(
            new AuthError("INVALID_INPUT", "idempotencyKey is required for OAuth2 callbacks.", 400, [
              createIssue("idempotencyKey is required when idempotency is enabled", ["idempotencyKey"]),
            ]),
          );
        }

        const first = await ctx.adapters.idempotency.checkAndSet(
          `oauth2:${input.provider}:${input.idempotencyKey}`,
          ctx.security?.oauth2IdempotencyTtlSeconds ?? 300,
        );
        if (!first) {
          return errorOperation(
            new AuthError("CONFLICT", "Duplicate OAuth2 callback.", 409, [
              createIssue("Duplicate OAuth2 callback", ["idempotencyKey"]),
            ]),
          );
        }
      }

      if ((providerConfig.pkceRequired ?? true) && !input.codeVerifier) {
        return errorOperation(
          new AuthError("INVALID_INPUT", "Missing OAuth2 PKCE code verifier.", 400, [
            createIssue("codeVerifier is required for this provider", ["codeVerifier"]),
          ]),
        );
      }

      let tokens: OAuth2Tokens;
      try {
        tokens = await providerConfig.exchangeAuthorizationCode({
          authorizationCode: input.authorizationCode,
          codeVerifier: input.codeVerifier,
          redirectUri: input.redirectUri,
        });
      } catch (error) {
        if (error instanceof OAuth2RequestError) {
          return errorOperation(
            new AuthError("OAUTH2_EXCHANGE_FAILED", "OAuth2 code exchange failed.", 400, [
              createIssue(error.description ?? error.code, ["authorizationCode"]),
            ]),
          );
        }
        if (error instanceof ArcticFetchError) {
          return errorOperation(
            new AuthError("OAUTH2_EXCHANGE_FAILED", "OAuth2 provider is unreachable right now.", 502, [
              createIssue("Provider request failed", ["provider"]),
            ]),
          );
        }
        return errorOperation(new AuthError("OAUTH2_EXCHANGE_FAILED", "OAuth2 code exchange failed.", 502));
      }

      let exchanged: OAuth2ResolvedProfile<U, P>;
      try {
        exchanged = await providerConfig.resolveProfile({
          provider: input.provider,
          tokens,
          authenticateInput: input,
        });
      } catch {
        return errorOperation(new AuthError("OAUTH2_EXCHANGE_FAILED", "Failed to resolve OAuth2 profile.", 502));
      }

      if (!exchanged.providerUserId || exchanged.providerUserId.trim() === "") {
        return errorOperation(
          new AuthError("OAUTH2_EXCHANGE_FAILED", "OAuth2 profile is missing provider user id.", 502, [
            createIssue("Provider user id is required", ["provider"]),
          ]),
        );
      }

      const linkedUserId = await config.accounts.findUserId(input.provider, exchanged.providerUserId);
      if (linkedUserId) {
        const linkedUser = await ctx.adapters.users.findById(linkedUserId);
        if (!linkedUser) {
          return errorOperation(new AuthError("USER_NOT_FOUND", "User not found.", 404));
        }

        return successOperation({ user: linkedUser });
      }

      const normalizedEmail = exchanged.email?.trim().toLowerCase();
      if (!normalizedEmail) {
        return errorOperation(
          new AuthError("INVALID_INPUT", "OAuth2 provider did not return a usable email.", 400, [
            createIssue("Email is required", ["email"]),
          ]),
        );
      }

      const accessToken = getAccessToken(tokens);
      const refreshToken = getRefreshToken(tokens);
      const continuation: OAuth2PendingContinuation<P> = {
        provider: input.provider,
        providerUserId: exchanged.providerUserId,
        accessToken,
        refreshToken,
      };

      const existing = await ctx.adapters.users.findByEmail(normalizedEmail);
      if (existing) {
        await config.accounts.linkAccount({
          userId: existing.id,
          provider: input.provider,
          providerUserId: exchanged.providerUserId,
          accessToken,
          refreshToken,
        });
        return successOperation({ user: existing });
      }

      const profileRecord: Record<string, unknown> = {
        ...(exchanged.profile as Record<string, unknown> | undefined),
        email: normalizedEmail,
        emailVerified: exchanged.emailVerified ?? false,
      };

      const requiredError = ensureFields(profileRecord, requiredProfileFields.map(String));
      if (requiredError) {
        const pending = ctx.adapters.pendingProfiles;
        if (!pending) {
          return errorOperation(
            new AuthError(
              "PLUGIN_MISCONFIGURED",
              "Pending profile adapter is required for partial OAuth2 profiles.",
              500,
            ),
          );
        }

        const missingFields = requiredError.issues
          .map((issue) => issue.path?.[0])
          .filter((path): path is Extract<keyof U, string> => typeof path === "string");

        const pendingProfileId = createId();
        const meta = {
          pendingProfileId,
          sourceMethod: "oauth2" as const,
          email: normalizedEmail,
          missingFields,
          prefill: profileRecord as Partial<U>,
          continuation: continuation as Record<string, unknown>,
        };

        await pending.create({
          ...meta,
          expiresAt: addSeconds(ctx.now(), ttl),
          consumedAt: null,
        });

        return errorOperation(
          new AuthError(
            "PROFILE_COMPLETION_REQUIRED",
            "Additional profile fields are required.",
            400,
            requiredError.issues,
            meta as unknown as Record<string, unknown>,
          ),
          requiredError.issues,
        );
      }

      const user = await ctx.adapters.users.create(profileRecord as Omit<U, "id" | "createdAt" | "updatedAt">);

      await config.accounts.linkAccount({
        userId: user.id,
        provider: input.provider,
        providerUserId: exchanged.providerUserId,
        accessToken,
        refreshToken,
      });

      return successOperation({ user });
    },
  };
};
