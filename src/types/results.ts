import type { Issue } from "../issues/index.js";
import type { ProfileCompletionRequiredError, TwoFactorRequiredError, AuthError } from "../errors/index.js";
import type { UserBase } from "./model.js";

export type OperationResult<TData> =
  | { ok: true; data: TData; issues: Issue[] }
  | { ok: false; error: AuthError; issues: Issue[] };

export type AuthResult<U extends UserBase> =
  | { ok: true; user: U; sessionId: string; issues: Issue[] }
  | {
      ok: false;
      error: AuthError | TwoFactorRequiredError | ProfileCompletionRequiredError<U>;
      issues: Issue[];
    };

export const successResult = <U extends UserBase>(
  user: U,
  sessionId: string,
  issues: Issue[] = [],
): AuthResult<U> => ({ ok: true, user, sessionId, issues });

export const errorResult = <U extends UserBase>(
  error: AuthError | TwoFactorRequiredError | ProfileCompletionRequiredError<U>,
  issues: Issue[] = error.issues,
): AuthResult<U> => ({ ok: false, error, issues });

export const successOperation = <TData>(
  data: TData,
  issues: Issue[] = [],
): OperationResult<TData> => ({ ok: true, data, issues });

export const errorOperation = <TData = never>(
  error: AuthError,
  issues: Issue[] = error.issues,
): OperationResult<TData> => ({ ok: false, error, issues });
