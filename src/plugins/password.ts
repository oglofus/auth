import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type { PasswordCredentialAdapter } from "../types/adapters.js";
import type {
  PasswordAuthenticateInput,
  PasswordRegisterInput,
  UserBase,
} from "../types/model.js";
import type { AuthMethodPlugin } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";
import { cloneWithout, secretHash, secretVerify } from "../core/utils.js";
import { ensureFields } from "../core/validators.js";

export type PasswordPluginConfig<U extends UserBase, K extends keyof U> = {
  requiredProfileFields: readonly K[];
  credentials: PasswordCredentialAdapter;
  hashPassword?: (password: string) => string;
  verifyPassword?: (password: string, hash: string) => boolean;
};

export const passwordPlugin = <U extends UserBase, K extends keyof U>(
  config: PasswordPluginConfig<U, K>,
): AuthMethodPlugin<
  "password",
  PasswordRegisterInput<U, K>,
  PasswordAuthenticateInput,
  U
> => ({
  kind: "auth_method",
  method: "password",
  version: "2.0.0",
  supports: {
    register: true,
  },
  issueFields: {
    authenticate: ["email", "password"],
    register: ["email", "password", ...config.requiredProfileFields.map(String)] as any,
  },
  register: async (ctx, input) => {
    const exists = await ctx.adapters.users.findByEmail(input.email);
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

    const payload = cloneWithout(input as unknown as Record<string, unknown>, [
      "method",
      "password",
    ] as const);

    if (payload.emailVerified === undefined) {
      payload.emailVerified = false;
    }

    const user = await ctx.adapters.users.create(payload as Omit<U, "id" | "createdAt" | "updatedAt">);
    const hash = config.hashPassword ? config.hashPassword(input.password) : secretHash(input.password);
    await config.credentials.setPasswordHash(user.id, hash);

    return successOperation({ user });
  },
  authenticate: async (ctx, input) => {
    const user = await ctx.adapters.users.findByEmail(input.email);
    if (!user) {
      return errorOperation(
        new AuthError("INVALID_CREDENTIALS", "Invalid credentials.", 401, [
          createIssue("Invalid credentials", ["email"]),
        ]),
      );
    }

    const storedHash = await config.credentials.getPasswordHash(user.id);
    if (!storedHash) {
      return errorOperation(new AuthError("INVALID_CREDENTIALS", "Invalid credentials.", 401));
    }

    const ok = config.verifyPassword
      ? config.verifyPassword(input.password, storedHash)
      : secretVerify(input.password, storedHash);

    if (!ok) {
      return errorOperation(
        new AuthError("INVALID_CREDENTIALS", "Invalid credentials.", 401, [
          createIssue("Invalid credentials", ["password"]),
        ]),
      );
    }

    return successOperation({ user });
  },
});
