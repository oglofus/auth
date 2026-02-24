import { ArcticFetchError, OAuth2RequestError, type OAuth2Tokens } from "arctic";
import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type { OAuth2AccountAdapter } from "../types/adapters.js";
import type { OAuth2AuthenticateInput, UserBase } from "../types/model.js";
import type { AuthMethodPlugin } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";
import { addSeconds, createId } from "../core/utils.js";
import { ensureFields } from "../core/validators.js";

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

export type OAuth2ResolvedProfile<U extends UserBase, P extends string> = {
  provider?: P;
  providerUserId: string;
  email?: string;
  emailVerified?: boolean;
  profile?: Partial<U>;
};

export type OAuth2ProviderConfig<U extends UserBase, P extends string> = {
  client: ArcticAuthorizationCodeClient;
  resolveProfile: (input: {
    provider: P;
    tokens: OAuth2Tokens;
    authenticateInput: OAuth2AuthenticateInput<P>;
  }) => Promise<OAuth2ResolvedProfile<U, P>>;
  pkceRequired?: boolean;
};

export type OAuth2PluginConfig<
  U extends UserBase,
  P extends string,
  K extends keyof U = never,
> = {
  providers: { [Provider in P]: OAuth2ProviderConfig<U, Provider> };
  accounts: OAuth2AccountAdapter<P>;
  requiredProfileFields?: readonly K[];
  pendingProfileTtlSeconds?: number;
};

const exchangeAuthorizationCode = async (
  client: ArcticAuthorizationCodeClient,
  authorizationCode: string,
  codeVerifier: string | null,
): Promise<OAuth2Tokens> => {
  const validateAuthorizationCode = client.validateAuthorizationCode as (
    code: string,
    verifier: string | null,
  ) => Promise<OAuth2Tokens>;
  return validateAuthorizationCode(authorizationCode, codeVerifier);
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

export const oauth2Plugin = <
  U extends UserBase,
  P extends string,
  K extends keyof U = never,
>(
  config: OAuth2PluginConfig<U, P, K>,
): AuthMethodPlugin<
  "oauth2",
  OAuth2AuthenticateInput<P>,
  OAuth2AuthenticateInput<P>,
  U
> => {
  const ttl = config.pendingProfileTtlSeconds ?? 10 * 60;
  const requiredProfileFields = (config.requiredProfileFields ?? []) as readonly K[];

  return {
    kind: "auth_method",
    method: "oauth2",
    version: "1.0.0",
    supports: {
      register: false,
    },
    issueFields: {
      authenticate: ["provider", "authorizationCode", "redirectUri", "codeVerifier"],
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

      if ((providerConfig.pkceRequired ?? true) && !input.codeVerifier) {
        return errorOperation(
          new AuthError("INVALID_INPUT", "Missing OAuth2 PKCE code verifier.", 400, [
            createIssue("codeVerifier is required for this provider", ["codeVerifier"]),
          ]),
        );
      }

      let tokens: OAuth2Tokens;
      try {
        tokens = await exchangeAuthorizationCode(
          providerConfig.client,
          input.authorizationCode,
          input.codeVerifier ?? null,
        );
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
            new AuthError(
              "OAUTH2_EXCHANGE_FAILED",
              "OAuth2 provider is unreachable right now.",
              502,
              [createIssue("Provider request failed", ["provider"])],
            ),
          );
        }
        return errorOperation(
          new AuthError("OAUTH2_EXCHANGE_FAILED", "OAuth2 code exchange failed.", 502),
        );
      }

      let exchanged: OAuth2ResolvedProfile<U, P>;
      try {
        exchanged = await providerConfig.resolveProfile({
          provider: input.provider,
          tokens,
          authenticateInput: input,
        });
      } catch {
        return errorOperation(
          new AuthError("OAUTH2_EXCHANGE_FAILED", "Failed to resolve OAuth2 profile.", 502),
        );
      }

      if (!exchanged.providerUserId || exchanged.providerUserId.trim() === "") {
        return errorOperation(
          new AuthError("OAUTH2_EXCHANGE_FAILED", "OAuth2 profile is missing provider user id.", 502, [
            createIssue("Provider user id is required", ["provider"]),
          ]),
        );
      }

      const linkedUserId = await config.accounts.findUserId(
        input.provider,
        exchanged.providerUserId,
      );
      if (linkedUserId) {
        const linkedUser = await ctx.adapters.users.findById(linkedUserId);
        if (!linkedUser) {
          return errorOperation(new AuthError("USER_NOT_FOUND", "User not found.", 404));
        }

        return successOperation({ user: linkedUser });
      }

      const normalizedEmail = exchanged.email?.trim().toLowerCase();
      const accessToken = getAccessToken(tokens);
      const refreshToken = getRefreshToken(tokens);
      if (normalizedEmail) {
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
      }

      const profileRecord: Record<string, unknown> = {
        ...(exchanged.profile as Record<string, unknown> | undefined),
      };

      if (normalizedEmail) {
        profileRecord.email = normalizedEmail;
      }
      if (exchanged.emailVerified !== undefined) {
        profileRecord.emailVerified = exchanged.emailVerified;
      }

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
          sourceMethod: "oauth2",
          email: normalizedEmail,
          missingFields,
          prefill: exchanged.profile ?? {},
        } as const;

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

      if (!normalizedEmail) {
        return errorOperation(
          new AuthError("INVALID_INPUT", "OAuth2 provider did not return a usable email.", 400, [
            createIssue("Email is required", ["email"]),
          ]),
        );
      }

      const newUserPayload = {
        ...profileRecord,
        email: normalizedEmail,
        emailVerified: exchanged.emailVerified ?? false,
      };

      const user = await ctx.adapters.users.create(
        newUserPayload as Omit<U, "id" | "createdAt" | "updatedAt">,
      );

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
