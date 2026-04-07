import { addSeconds, cloneWithout, createId, createNumericCode, secretHash, secretVerify } from "../core/utils.js";
import { ensureFields } from "../core/validators.js";
import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type { EmailOtpPluginHandlers } from "../types/adapters.js";
import type { EmailOtpAuthenticateInput, EmailOtpRegisterInput, UserBase } from "../types/model.js";
import type { AuthMethodPlugin, EmailOtpPluginApi } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";

export type EmailOtpPluginConfig<U extends UserBase, K extends keyof U> = {
  requiredProfileFields: readonly K[];
  otp: EmailOtpPluginHandlers["otp"];
  delivery: EmailOtpPluginHandlers["delivery"];
  challengeTtlSeconds?: number;
  maxAttempts?: number;
  codeLength?: number;
};

const PENDING_PREFIX = "pending:";
const EMAIL_OTP_REQUEST_POLICY = { limit: 3, windowSeconds: 300 };
const OTP_VERIFY_POLICY = { limit: 10, windowSeconds: 300 };

const isPendingUserId = (value: string): boolean => value.startsWith(PENDING_PREFIX);

const createRateLimitedError = (retryAfterSeconds?: number): AuthError =>
  new AuthError(
    "RATE_LIMITED",
    "Too many requests.",
    429,
    [],
    retryAfterSeconds === undefined ? undefined : { retryAfterSeconds },
  );

export const emailOtpPlugin = <U extends UserBase, K extends keyof U>(
  config: EmailOtpPluginConfig<U, K>,
): AuthMethodPlugin<
  "email_otp",
  EmailOtpRegisterInput<U, K>,
  EmailOtpAuthenticateInput,
  U,
  EmailOtpPluginApi,
  true,
  true
> => {
  const ttl = config.challengeTtlSeconds ?? 10 * 60;
  const maxAttempts = config.maxAttempts ?? 5;
  const codeLength = config.codeLength ?? 6;

  const verifyChallenge = async (
    challengeId: string,
    code: string,
    now: Date,
    request?: { ip?: string },
    security?: { rateLimits?: { otpVerify?: { limit: number; windowSeconds: number } } },
    rateLimiter?: {
      consume(
        key: string,
        limit: number,
        windowSeconds: number,
      ): Promise<{ allowed: boolean; retryAfterSeconds?: number }>;
    },
  ): Promise<{ ok: true; userId: string; email: string } | { ok: false; error: AuthError }> => {
    const challenge = await config.otp.findChallengeById(challengeId);
    if (rateLimiter) {
      const policy = security?.rateLimits?.otpVerify ?? OTP_VERIFY_POLICY;
      const result = await rateLimiter.consume(
        request?.ip
          ? `otpVerify:ip:${request.ip}:identity:${challenge?.email ?? `challenge:${challengeId}`}`
          : `otpVerify:identity:${challenge?.email ?? `challenge:${challengeId}`}`,
        policy.limit,
        policy.windowSeconds,
      );
      if (!result.allowed) {
        return {
          ok: false,
          error: createRateLimitedError(result.retryAfterSeconds),
        };
      }
    }

    if (!challenge) {
      return {
        ok: false,
        error: new AuthError("OTP_INVALID", "Invalid OTP challenge.", 400, [
          createIssue("Invalid challenge", ["challengeId"]),
        ]),
      };
    }

    if (challenge.expiresAt.getTime() <= now.getTime()) {
      return {
        ok: false,
        error: new AuthError("OTP_EXPIRED", "OTP has expired.", 400, [createIssue("OTP expired", ["code"])]),
      };
    }

    if (challenge.attempts >= maxAttempts) {
      return {
        ok: false,
        error: new AuthError("RATE_LIMITED", "Too many OTP attempts.", 429),
      };
    }

    const valid = secretVerify(code, challenge.codeHash);
    if (!valid) {
      const attempts = await config.otp.incrementAttempts(challengeId);
      if (attempts.attempts >= maxAttempts) {
        return {
          ok: false,
          error: new AuthError("RATE_LIMITED", "Too many OTP attempts.", 429),
        };
      }

      return {
        ok: false,
        error: new AuthError("OTP_INVALID", "Invalid OTP code.", 400, [createIssue("Invalid code", ["code"])]),
      };
    }

    const consumed = await config.otp.consumeChallenge(challengeId);
    if (!consumed) {
      return {
        ok: false,
        error: new AuthError("OTP_INVALID", "OTP already used.", 400, [
          createIssue("Challenge already consumed", ["challengeId"]),
        ]),
      };
    }

    return {
      ok: true,
      userId: challenge.userId,
      email: challenge.email,
    };
  };

  return {
    kind: "auth_method",
    method: "email_otp",
    version: "2.0.0",
    supports: {
      register: true,
    },
    issueFields: {
      authenticate: ["challengeId", "code"],
      register: ["challengeId", "code", ...config.requiredProfileFields.map(String)] as any,
    },
    createApi: (ctx) => ({
      request: async (input, request) => {
        const email = input.email.trim().toLowerCase();
        if (ctx.adapters.rateLimiter) {
          const policy = ctx.security?.rateLimits?.emailOtpRequest ?? EMAIL_OTP_REQUEST_POLICY;
          const limited = await ctx.adapters.rateLimiter.consume(
            request?.ip ? `emailOtpRequest:ip:${request.ip}:identity:${email}` : `emailOtpRequest:identity:${email}`,
            policy.limit,
            policy.windowSeconds,
          );
          if (!limited.allowed) {
            return errorOperation(createRateLimitedError(limited.retryAfterSeconds));
          }
        }

        const user = await ctx.adapters.users.findByEmail(email);

        const code = createNumericCode(codeLength);
        const challenge = await config.otp.createChallenge({
          userId: user?.id ?? `${PENDING_PREFIX}${createId()}`,
          email,
          codeHash: secretHash(code),
          expiresAt: addSeconds(ctx.now(), ttl),
        });

        const delivery = await config.delivery.send({
          email,
          code,
          expiresAt: challenge.expiresAt,
          requestId: request?.requestId,
          userId: user?.id,
          locale: input.locale,
        });

        if (!delivery.accepted && !ctx.adapters.outbox) {
          return errorOperation(new AuthError("DELIVERY_FAILED", "Unable to deliver OTP.", 502));
        }

        if (!delivery.accepted && ctx.adapters.outbox) {
          await ctx.adapters.outbox.enqueue({
            id: createId(),
            channel: "email",
            to: email,
            payload: {
              kind: "email_otp",
              challengeId: challenge.id,
            },
            attempts: 0,
            nextAttemptAt: ctx.now(),
          });

          return successOperation({ disposition: "queued", challengeId: challenge.id });
        }

        return successOperation({ disposition: "sent", challengeId: challenge.id });
      },
    }),
    register: async (ctx, input) => {
      const verified = await verifyChallenge(
        input.challengeId,
        input.code,
        ctx.now(),
        ctx.request,
        ctx.security,
        ctx.adapters.rateLimiter,
      );
      if (!verified.ok) {
        return errorOperation(verified.error);
      }

      const exists = await ctx.adapters.users.findByEmail(verified.email);
      if (exists) {
        return errorOperation(
          new AuthError("ACCOUNT_EXISTS", "An account already exists for this email.", 409, [
            createIssue("Email already registered", ["email"]),
          ]),
        );
      }

      const requiredError = ensureFields(
        input as unknown as Record<string, unknown>,
        config.requiredProfileFields.map(String),
      );
      if (requiredError) {
        return errorOperation(requiredError);
      }

      const payload = cloneWithout(
        input as unknown as Record<string, unknown>,
        ["method", "challengeId", "code"] as const,
      );
      payload.email = verified.email;
      payload.emailVerified = true;

      const user = await ctx.adapters.users.create(payload as Omit<U, "id" | "createdAt" | "updatedAt">);
      return successOperation({ user });
    },
    authenticate: async (ctx, input) => {
      const verified = await verifyChallenge(
        input.challengeId,
        input.code,
        ctx.now(),
        ctx.request,
        ctx.security,
        ctx.adapters.rateLimiter,
      );
      if (!verified.ok) {
        return errorOperation(verified.error);
      }

      if (isPendingUserId(verified.userId)) {
        return errorOperation(
          new AuthError("ACCOUNT_NOT_FOUND", "No account found for this OTP challenge.", 404, [
            createIssue("No account for this email", ["challengeId"]),
          ]),
        );
      }

      const user = await ctx.adapters.users.findById(verified.userId);
      if (!user) {
        return errorOperation(new AuthError("USER_NOT_FOUND", "User not found.", 404));
      }

      return successOperation({ user });
    },
  };
};
