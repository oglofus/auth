import { addSeconds, cloneWithout, createId, createToken, deterministicTokenHash } from "../core/utils.js";
import { ensureFields } from "../core/validators.js";
import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type { MagicLinkPluginHandlers } from "../types/adapters.js";
import type { MagicLinkAuthenticateInput, MagicLinkRegisterInput, UserBase } from "../types/model.js";
import type { AuthMethodPlugin, MagicLinkPluginApi } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";

export type MagicLinkPluginConfig<U extends UserBase, K extends keyof U> = {
  requiredProfileFields: readonly K[];
  links: MagicLinkPluginHandlers["links"];
  delivery: MagicLinkPluginHandlers["delivery"];
  tokenTtlSeconds?: number;
  baseVerifyUrl: string;
};

const MAGIC_LINK_REQUEST_POLICY = { limit: 3, windowSeconds: 300 };

const createRateLimitedError = (retryAfterSeconds?: number): AuthError =>
  new AuthError(
    "RATE_LIMITED",
    "Too many requests.",
    429,
    [],
    retryAfterSeconds === undefined ? undefined : { retryAfterSeconds },
  );

export const magicLinkPlugin = <U extends UserBase, K extends keyof U>(
  config: MagicLinkPluginConfig<U, K>,
): AuthMethodPlugin<"magic_link", MagicLinkRegisterInput<U, K>, MagicLinkAuthenticateInput, U, MagicLinkPluginApi, true, true> => {
  const ttl = config.tokenTtlSeconds ?? 15 * 60;

  const verifyToken = async (
    token: string,
    now: Date,
  ): Promise<{ ok: true; userId?: string; email: string; tokenId: string } | { ok: false; error: AuthError }> => {
    const candidate = await config.links.findActiveTokenByHash(deterministicTokenHash(token, "magic_link"));

    if (!candidate) {
      return {
        ok: false,
        error: new AuthError("MAGIC_LINK_INVALID", "Invalid magic link.", 400, [
          createIssue("Invalid token", ["token"]),
        ]),
      };
    }

    if (candidate.expiresAt.getTime() <= now.getTime()) {
      return {
        ok: false,
        error: new AuthError("MAGIC_LINK_EXPIRED", "Magic link expired.", 400, [
          createIssue("Expired token", ["token"]),
        ]),
      };
    }

    const consumed = await config.links.consumeToken(candidate.id);
    if (!consumed) {
      return {
        ok: false,
        error: new AuthError("MAGIC_LINK_INVALID", "Magic link already used.", 400),
      };
    }

    return {
      ok: true,
      userId: candidate.userId,
      email: candidate.email,
      tokenId: candidate.id,
    };
  };

  return {
    kind: "auth_method",
    method: "magic_link",
    version: "2.0.0",
    supports: {
      register: true,
    },
    issueFields: {
      authenticate: ["token"],
      register: ["token", ...config.requiredProfileFields.map(String)] as any,
    },
    createApi: (ctx) => ({
      request: async (input, request) => {
        const email = input.email.trim().toLowerCase();
        if (ctx.adapters.rateLimiter) {
          const policy = ctx.security?.rateLimits?.magicLinkRequest ?? MAGIC_LINK_REQUEST_POLICY;
          const limited = await ctx.adapters.rateLimiter.consume(
            request?.ip ? `magicLinkRequest:ip:${request.ip}:identity:${email}` : `magicLinkRequest:identity:${email}`,
            policy.limit,
            policy.windowSeconds,
          );
          if (!limited.allowed) {
            return errorOperation(createRateLimitedError(limited.retryAfterSeconds));
          }
        }

        const user = await ctx.adapters.users.findByEmail(email);
        const rawToken = createToken();
        const tokenHash = deterministicTokenHash(rawToken, "magic_link");
        const expiresAt = addSeconds(ctx.now(), ttl);

        const token = await config.links.createToken({
          userId: user?.id,
          email,
          tokenHash,
          expiresAt,
        });

        const link = `${config.baseVerifyUrl}?token=${encodeURIComponent(rawToken)}`;
        const delivery = await config.delivery.send({
          email,
          link,
          expiresAt,
          requestId: request?.requestId,
          userId: user?.id,
          locale: input.locale,
        });

        if (!delivery.accepted && !ctx.adapters.outbox) {
          return errorOperation(new AuthError("DELIVERY_FAILED", "Unable to send magic link.", 502));
        }

        if (!delivery.accepted && ctx.adapters.outbox) {
          await ctx.adapters.outbox.enqueue({
            id: createId(),
            channel: "email",
            to: email,
            payload: {
              kind: "magic_link",
              tokenId: token.id,
            },
            attempts: 0,
            nextAttemptAt: ctx.now(),
          });

          return successOperation({ disposition: "queued", tokenId: token.id });
        }

        return successOperation({ disposition: "sent", tokenId: token.id });
      },
    }),
    register: async (ctx, input) => {
      const verified = await verifyToken(input.token, ctx.now());
      if (!verified.ok) {
        return errorOperation(verified.error);
      }

      const exists = await ctx.adapters.users.findByEmail(verified.email);
      if (exists) {
        return errorOperation(new AuthError("ACCOUNT_EXISTS", "Account already exists.", 409));
      }

      const requiredError = ensureFields(
        input as unknown as Record<string, unknown>,
        config.requiredProfileFields.map(String),
      );
      if (requiredError) {
        return errorOperation(requiredError);
      }

      const payload = cloneWithout(input as unknown as Record<string, unknown>, ["method", "token"] as const);
      payload.email = verified.email;
      payload.emailVerified = true;

      const user = await ctx.adapters.users.create(payload as Omit<U, "id" | "createdAt" | "updatedAt">);
      return successOperation({ user });
    },
    authenticate: async (ctx, input) => {
      const verified = await verifyToken(input.token, ctx.now());
      if (!verified.ok) {
        return errorOperation(verified.error);
      }

      if (!verified.userId) {
        return errorOperation(new AuthError("ACCOUNT_NOT_FOUND", "No account for this magic link.", 404));
      }

      const user = await ctx.adapters.users.findById(verified.userId);
      if (!user) {
        return errorOperation(new AuthError("USER_NOT_FOUND", "User not found.", 404));
      }

      return successOperation({ user });
    },
  };
};
