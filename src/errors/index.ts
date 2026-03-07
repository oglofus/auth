import type { Issue } from "../issues/index.js";
import type { ProfileCompletionState, TwoFactorRequiredMeta, UserBase } from "../types/model.js";

export type AuthErrorCode =
  | "INVALID_INPUT"
  | "METHOD_DISABLED"
  | "METHOD_NOT_REGISTERABLE"
  | "ACCOUNT_NOT_FOUND"
  | "ACCOUNT_EXISTS"
  | "ACCOUNT_EXISTS_WITH_DIFFERENT_METHOD"
  | "ORGANIZATION_NOT_FOUND"
  | "MEMBERSHIP_NOT_FOUND"
  | "MEMBERSHIP_FORBIDDEN"
  | "ROLE_INVALID"
  | "ROLE_NOT_ASSIGNABLE"
  | "ORGANIZATION_INVITE_INVALID"
  | "ORGANIZATION_INVITE_EXPIRED"
  | "SEAT_LIMIT_REACHED"
  | "FEATURE_DISABLED"
  | "LIMIT_EXCEEDED"
  | "LAST_OWNER_GUARD"
  | "SESSION_NOT_FOUND"
  | "INVALID_CREDENTIALS"
  | "USER_NOT_FOUND"
  | "CONFLICT"
  | "RATE_LIMITED"
  | "DELIVERY_FAILED"
  | "EMAIL_NOT_VERIFIED"
  | "OTP_EXPIRED"
  | "OTP_INVALID"
  | "MAGIC_LINK_EXPIRED"
  | "MAGIC_LINK_INVALID"
  | "OAUTH2_PROVIDER_DISABLED"
  | "OAUTH2_EXCHANGE_FAILED"
  | "PASSKEY_INVALID_ASSERTION"
  | "PASSKEY_INVALID_ATTESTATION"
  | "PASSKEY_CHALLENGE_EXPIRED"
  | "CUSTOMER_NOT_FOUND"
  | "SUBSCRIPTION_NOT_FOUND"
  | "SUBSCRIPTION_ALREADY_EXISTS"
  | "TRIAL_NOT_AVAILABLE"
  | "STRIPE_WEBHOOK_INVALID"
  | "PROFILE_COMPLETION_REQUIRED"
  | "PROFILE_COMPLETION_EXPIRED"
  | "TWO_FACTOR_REQUIRED"
  | "TWO_FACTOR_INVALID"
  | "TWO_FACTOR_EXPIRED"
  | "RECOVERY_CODE_INVALID"
  | "PLUGIN_METHOD_CONFLICT"
  | "PLUGIN_MISCONFIGURED"
  | "INTERNAL_ERROR";

export class AuthError extends Error {
  constructor(
    public readonly code: AuthErrorCode,
    message: string,
    public readonly status: number,
    public readonly issues: Issue[] = [],
    public readonly meta?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export type TwoFactorRequiredError = AuthError & {
  code: "TWO_FACTOR_REQUIRED";
  meta: TwoFactorRequiredMeta;
};

export type ProfileCompletionRequiredError<U extends UserBase> = AuthError & {
  code: "PROFILE_COMPLETION_REQUIRED";
  meta: ProfileCompletionState<U>;
};

export const authError = (
  code: AuthErrorCode,
  message: string,
  status: number,
  issues: Issue[] = [],
  meta?: Record<string, unknown>,
): AuthError => new AuthError(code, message, status, issues, meta);
