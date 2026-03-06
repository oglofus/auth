import { randomBytes } from "node:crypto";
import { createTOTPKeyURI, generateTOTP, verifyTOTPWithGracePeriod } from "@oslojs/otp";
import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import { addSeconds, createId, createToken, secretHash } from "../core/utils.js";
import type {
  RecoveryCodeAdapter,
  TotpAdapter,
  TwoFactorChallengeAdapter,
} from "../types/adapters.js";
import type { AuthRequestContext, SecondFactorMethod, TwoFactorVerifyInput, UserBase } from "../types/model.js";
import type { DomainPlugin, TwoFactorPluginApi } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";

export type TwoFactorPluginConfig<U extends UserBase> = {
  requiredMethods: readonly SecondFactorMethod[];
  challenges: TwoFactorChallengeAdapter;
  totp?: TotpAdapter;
  recoveryCodes?: RecoveryCodeAdapter;
  shouldRequire?: (input: {
    user: U;
    primaryMethod: string;
    request?: AuthRequestContext;
  }) => boolean | Promise<boolean>;
  challengeTtlSeconds?: number;
  issuer?: string;
};

type Enrollment = {
  userId: string;
  secret: string;
};

const TOTP_INTERVAL_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_GRACE_SECONDS = 30;

const toTotpKey = (secret: string): Uint8Array => Buffer.from(secret, "base64url");

const verifyTotpCode = (secret: string, code: string): boolean => {
  try {
    return verifyTOTPWithGracePeriod(
      toTotpKey(secret),
      TOTP_INTERVAL_SECONDS,
      TOTP_DIGITS,
      code,
      TOTP_GRACE_SECONDS,
    );
  } catch {
    return false;
  }
};

const generateTotpForTest = (secret: string, at = new Date()): string => {
  const originalNow = Date.now;
  Date.now = () => at.getTime();
  try {
    return generateTOTP(toTotpKey(secret), TOTP_INTERVAL_SECONDS, TOTP_DIGITS);
  } finally {
    Date.now = originalNow;
  }
};

const recoveryHash = (userId: string, code: string): string =>
  secretHash(code.toUpperCase(), `recovery:${userId}`);

export const twoFactorPlugin = <U extends UserBase>(
  config: TwoFactorPluginConfig<U>,
): DomainPlugin<"two_factor", U, TwoFactorPluginApi<U>> => {
  const enrollments = new Map<string, Enrollment>();
  const challengeTtl = config.challengeTtlSeconds ?? 5 * 60;
  const issuer = config.issuer ?? "OglofusAuth";

  return {
    kind: "domain",
    method: "two_factor",
    version: "2.0.0",
    createApi: (ctx) => ({
      evaluatePrimary: async (input, request) => {
        const mustRequire = config.shouldRequire
          ? await config.shouldRequire({ user: input.user, primaryMethod: input.primaryMethod, request })
          : config.requiredMethods.length > 0;

        if (!mustRequire) {
          return successOperation({ required: false });
        }

        const pendingAuthId = createId();
        await config.challenges.create({
          id: pendingAuthId,
          userId: input.user.id,
          primaryMethod: input.primaryMethod,
          availableSecondFactors: [...config.requiredMethods],
          expiresAt: addSeconds(ctx.now(), challengeTtl),
          consumedAt: null,
        });

        return successOperation({
          required: true,
          pendingAuthId,
          availableSecondFactors: [...config.requiredMethods],
        });
      },
      verify: async (input) => {
        const challenge = await config.challenges.findById(input.pendingAuthId);
        if (!challenge) {
          return errorOperation(
            new AuthError("TWO_FACTOR_INVALID", "Invalid two-factor challenge.", 400, [
              createIssue("Unknown pending auth challenge", ["pendingAuthId"]),
            ]),
          );
        }

        if (challenge.expiresAt.getTime() <= ctx.now().getTime()) {
          return errorOperation(
            new AuthError("TWO_FACTOR_EXPIRED", "Two-factor challenge expired.", 400, [
              createIssue("Challenge expired", ["pendingAuthId"]),
            ]),
          );
        }

        if (!challenge.availableSecondFactors.includes(input.method)) {
          return errorOperation(
            new AuthError("TWO_FACTOR_INVALID", "Second factor method is not allowed.", 400),
          );
        }

        const user = await ctx.adapters.users.findById(challenge.userId);
        if (!user) {
          return errorOperation(new AuthError("USER_NOT_FOUND", "User not found.", 404));
        }

        if (input.method === "totp") {
          if (!config.totp) {
            return errorOperation(
              new AuthError("PLUGIN_MISCONFIGURED", "TOTP adapter missing in two_factor plugin.", 500),
            );
          }

          const secret = await config.totp.findActiveByUserId(user.id);
          if (!secret) {
            return errorOperation(new AuthError("TWO_FACTOR_INVALID", "TOTP is not configured.", 400));
          }

          if (!verifyTotpCode(secret.encryptedSecret, input.code)) {
            return errorOperation(
              new AuthError("TWO_FACTOR_INVALID", "Invalid TOTP code.", 400, [
                createIssue("Invalid TOTP code", ["code"]),
              ]),
            );
          }
        } else if (input.method === "recovery_code") {
          if (!config.recoveryCodes) {
            return errorOperation(
              new AuthError(
                "PLUGIN_MISCONFIGURED",
                "Recovery code adapter missing in two_factor plugin.",
                500,
              ),
            );
          }

          const consumed = await config.recoveryCodes.consume(
            user.id,
            recoveryHash(user.id, input.code),
          );
          if (!consumed) {
            return errorOperation(
              new AuthError("RECOVERY_CODE_INVALID", "Invalid recovery code.", 400, [
                createIssue("Invalid recovery code", ["code"]),
              ]),
            );
          }
        }

        const consumedChallenge = await config.challenges.consume(challenge.id);
        if (!consumedChallenge) {
          return errorOperation(
            new AuthError("TWO_FACTOR_INVALID", "Two-factor challenge already consumed.", 400),
          );
        }

        return successOperation({ user });
      },
      beginTotpEnrollment: async (userId) => {
        if (!config.totp) {
          return errorOperation(
            new AuthError("PLUGIN_MISCONFIGURED", "TOTP adapter missing in two_factor plugin.", 500),
          );
        }

        const enrollmentId = createId();
        const secret = randomBytes(20).toString("base64url");
        enrollments.set(enrollmentId, { userId, secret });

        const otpauthUri = createTOTPKeyURI(
          issuer,
          userId,
          toTotpKey(secret),
          TOTP_INTERVAL_SECONDS,
          TOTP_DIGITS,
        );

        return successOperation({
          enrollmentId,
          otpauthUri,
        });
      },
      confirmTotpEnrollment: async ({ enrollmentId, code }) => {
        if (!config.totp) {
          return errorOperation(
            new AuthError("PLUGIN_MISCONFIGURED", "TOTP adapter missing in two_factor plugin.", 500),
          );
        }

        const enrollment = enrollments.get(enrollmentId);
        if (!enrollment) {
          return errorOperation(new AuthError("TWO_FACTOR_INVALID", "Unknown enrollment id.", 400));
        }

        if (!verifyTotpCode(enrollment.secret, code)) {
          return errorOperation(
            new AuthError("TWO_FACTOR_INVALID", "Invalid TOTP code.", 400, [
              createIssue("Invalid TOTP code", ["code"]),
            ]),
          );
        }

        await config.totp.upsertActive(enrollment.userId, enrollment.secret);
        enrollments.delete(enrollmentId);
        return successOperation({ enabled: true as const });
      },
      regenerateRecoveryCodes: async (userId) => {
        if (!config.recoveryCodes) {
          return errorOperation(
            new AuthError(
              "PLUGIN_MISCONFIGURED",
              "Recovery code adapter missing in two_factor plugin.",
              500,
            ),
          );
        }

        const codes = Array.from({ length: 10 }, () => createToken(6).toUpperCase());
        const hashes = codes.map((code) => recoveryHash(userId, code));
        await config.recoveryCodes.replaceAll(userId, hashes);
        return successOperation({ codes });
      },
    }),
  };
};

export const testHelpers = {
  generateTotp: generateTotpForTest,
};
